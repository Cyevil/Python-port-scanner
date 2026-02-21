#!/usr/bin/env python3

import asyncio
import argparse
import csv
import json
import socket
import sys
import time
from datetime import datetime
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum simultaneous open connections. Tune down if you hit OS limits.
MAX_CONCURRENT = 500

# Probes sent to grab banners. Ordered by how generic they are.
BANNER_PROBES = [
    b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",  # HTTP probe
    b"\r\n",                                        # generic newline (works for FTP, SMTP, etc.)
]

# IANA service name lookup (common ports only; falls back to socket.getservbyport)
COMMON_SERVICES = {
    21: "ftp",       22: "ssh",       23: "telnet",    25: "smtp",
    53: "dns",       67: "dhcp",      68: "dhcp",      69: "tftp",
    80: "http",      110: "pop3",     111: "rpcbind",  119: "nntp",
    123: "ntp",      135: "msrpc",    137: "netbios",  138: "netbios",
    139: "netbios",  143: "imap",     161: "snmp",     162: "snmptrap",
    179: "bgp",      194: "irc",      389: "ldap",     443: "https",
    445: "smb",      465: "smtps",    514: "syslog",   515: "lpd",
    587: "smtp",     631: "ipp",      636: "ldaps",    993: "imaps",
    995: "pop3s",    1080: "socks",   1194: "openvpn", 1433: "mssql",
    1521: "oracle",  1723: "pptp",    2049: "nfs",     2082: "cpanel",
    2083: "cpanels", 2086: "whm",     2087: "whms",    2181: "zookeeper",
    2375: "docker",  2376: "dockertls", 3000: "dev-http", 3306: "mysql",
    3389: "rdp",     3690: "svn",     4369: "epmd",    5432: "postgresql",
    5672: "amqp",    5900: "vnc",     5984: "couchdb", 6379: "redis",
    6443: "k8s-api", 7001: "weblogic", 8080: "http-alt", 8443: "https-alt",
    8888: "jupyter", 9000: "php-fpm", 9042: "cassandra", 9200: "elasticsearch",
    9300: "es-transport", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb", 50000: "db2",  50070: "hadoop",
}

# ---------------------------------------------------------------------------
# Port parsing
# ---------------------------------------------------------------------------

def parse_ports(port_spec: str) -> List[int]:
    """
    Parse a port specification string into a sorted list of integer port numbers.

    Accepted formats:
      - Single port:   "80"
      - Range:         "1-1024"
      - Comma list:    "22,80,443"
      - Mixed:         "22,80-90,443,8000-8100"
    """
    ports: List[int] = []
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s.strip()), int(end_s.strip())
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                raise ValueError(f"Invalid port range: {part}")
            ports.extend(range(start, end + 1))
        else:
            port = int(part)
            if not (1 <= port <= 65535):
                raise ValueError(f"Port out of range: {port}")
            ports.append(port)

    # Deduplicate and sort
    return sorted(set(ports))


# ---------------------------------------------------------------------------
# Service name resolution
# ---------------------------------------------------------------------------

def get_service_name(port: int) -> str:
    """Return service name for a port, falling back to 'unknown'."""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


# ---------------------------------------------------------------------------
# Banner grabbing
# ---------------------------------------------------------------------------

async def grab_banner(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    timeout: float,
) -> Optional[str]:
    """
    Attempt to grab a banner from an already-open connection.
    Tries multiple probes and returns the first non-empty response.
    Returns None if nothing is received.
    """
    for probe in BANNER_PROBES:
        try:
            writer.write(probe)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            if data:
                # Decode bytes, replace unprintable chars, strip whitespace
                banner = data.decode("utf-8", errors="replace").strip()
                banner = " ".join(banner.split())  # collapse whitespace
                return banner[:200]  # cap length
        except (asyncio.TimeoutError, ConnectionError, OSError):
            continue
    return None


# ---------------------------------------------------------------------------
# Core port scanner coroutine
# ---------------------------------------------------------------------------

async def scan_port(
    host: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
    verbose: bool,
) -> dict:
    """
    Scan a single TCP port and return a result dict with keys:
      port, state, service, banner
    """
    result = {
        "port": port,
        "state": "closed",   # assume closed unless proven otherwise
        "service": get_service_name(port),
        "banner": "",
    }

    async with semaphore:
        try:
            # asyncio.open_connection raises ConnectionRefusedError for closed ports
            # and asyncio.TimeoutError / OSError for filtered / unreachable ports.
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )

            # Port is open — attempt banner grab
            result["state"] = "open"
            banner = await grab_banner(reader, writer, timeout=min(timeout, 2.0))
            if banner:
                result["banner"] = banner

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            if verbose:
                svc = result["service"]
                bnr = f" | {banner}" if banner else ""
                print(f"  [+] {port}/tcp  OPEN  {svc}{bnr}")

        except ConnectionRefusedError:
            result["state"] = "closed"
        except asyncio.TimeoutError:
            # No response within timeout — likely filtered by firewall
            result["state"] = "filtered"
        except OSError as exc:
            # Network-level errors (host unreachable, etc.)
            result["state"] = "filtered"
            if verbose:
                print(f"  [!] {port}/tcp  ERROR  {exc}", file=sys.stderr)

    return result


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

async def run_scan(
    host: str,
    ports: List[int],
    timeout: float,
    verbose: bool,
) -> List[dict]:
    """
    Launch all port scan coroutines concurrently and collect results.
    A semaphore limits the number of simultaneously open sockets.
    """
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    tasks = [
        scan_port(host, port, timeout, semaphore, verbose)
        for port in ports
    ]

    # asyncio.gather runs all coroutines concurrently in the event loop.
    # return_exceptions=True prevents one failure from cancelling all tasks.
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Filter out any unexpected exceptions (shouldn't happen, but be safe)
    clean: List[dict] = []
    for r in results:
        if isinstance(r, dict):
            clean.append(r)
        elif isinstance(r, Exception) and verbose:
            print(f"  [!] Unexpected error: {r}", file=sys.stderr)

    return sorted(clean, key=lambda x: x["port"])


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def print_table(results: List[dict], show_closed: bool = False) -> None:
    """Render results as a clean aligned table to stdout."""
    open_results    = [r for r in results if r["state"] == "open"]
    other_results   = [r for r in results if r["state"] != "open"]

    # Header
    sep = "─" * 80
    print(f"\n{sep}")
    print(f"{'PORT':<8} {'STATE':<10} {'SERVICE':<16} {'BANNER'}")
    print(sep)

    if not open_results:
        print("  No open ports found.")
    else:
        for r in open_results:
            banner_display = r["banner"][:45] + "…" if len(r["banner"]) > 45 else r["banner"]
            print(f"  {r['port']:<6} {'open':<10} {r['service']:<16} {banner_display}")

    if show_closed and other_results:
        print(f"\n{'─'*40} (closed / filtered)")
        for r in other_results:
            print(f"  {r['port']:<6} {r['state']:<10} {r['service']:<16}")

    print(sep)

    # Summary counts
    counts = {"open": 0, "closed": 0, "filtered": 0}
    for r in results:
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    print(
        f"  Summary: {counts['open']} open  |  "
        f"{counts['closed']} closed  |  {counts['filtered']} filtered\n"
    )


def save_json(results: List[dict], path: str) -> None:
    """Save results as a JSON file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"scan_results": results}, f, indent=2)
    print(f"  Results saved to {path} (JSON)")


def save_csv(results: List[dict], path: str) -> None:
    """Save results as a CSV file."""
    fieldnames = ["port", "state", "service", "banner"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print(f"  Results saved to {path} (CSV)")


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscanner",
        description=(
            "A fast, concurrent TCP port scanner with banner grabbing.\n\n"
            "Examples:\n"
            "  portscanner.py -t example.com -p 1-1024\n"
            "  portscanner.py -t 192.168.1.1 -p 22,80,443 -T 2 -v\n"
            "  portscanner.py -t scanme.nmap.org -p 1-1000 -o results.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        metavar="HOST",
        help="Target IP address or hostname to scan.",
    )
    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        metavar="PORTS",
        help=(
            "Port specification. Formats: single (80), range (1-1024), "
            "comma-list (22,80,443), or mixed (22,80-90,443). "
            "Default: 1-1024"
        ),
    )
    parser.add_argument(
        "-T", "--timeout",
        type=float,
        default=1.0,
        metavar="SECS",
        help=(
            "Connection timeout in seconds (float). Lower = faster but may "
            "miss slow hosts. Default: 1.0"
        ),
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        default=None,
        help=(
            "Save results to FILE. Format is inferred from extension: "
            ".json → JSON, .csv → CSV."
        ),
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print open ports in real time as they are discovered.",
    )
    parser.add_argument(
        "--show-closed",
        action="store_true",
        help="Include closed/filtered ports in the output table.",
    )

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # ── Resolve hostname ────────────────────────────────────────────────────
    try:
        resolved_ip = socket.gethostbyname(args.target)
    except socket.gaierror as exc:
        print(f"[ERROR] Cannot resolve host '{args.target}': {exc}", file=sys.stderr)
        sys.exit(1)

    # ── Parse ports ─────────────────────────────────────────────────────────
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"[ERROR] Invalid port specification: {exc}", file=sys.stderr)
        sys.exit(1)

    # ── Validate timeout ────────────────────────────────────────────────────
    if args.timeout <= 0:
        print("[ERROR] Timeout must be > 0", file=sys.stderr)
        sys.exit(1)

    # ── Print scan header ───────────────────────────────────────────────────
    start_time = time.time()
    print("═" * 80)
    print(f"  Port Scanner  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("═" * 80)
    print(f"  Target  : {args.target} ({resolved_ip})")
    print(f"  Ports   : {len(ports)} port(s)  [{ports[0]}–{ports[-1]}]")
    print(f"  Timeout : {args.timeout}s  |  Concurrency: {MAX_CONCURRENT} max")
    print("═" * 80)
    if args.verbose:
        print("  [Live output — open ports will appear below]\n")

    # ── Run async scan ──────────────────────────────────────────────────────
    try:
        results = asyncio.run(
            run_scan(
                host=resolved_ip,
                ports=ports,
                timeout=args.timeout,
                verbose=args.verbose,
            )
        )
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.", file=sys.stderr)
        sys.exit(130)

    elapsed = time.time() - start_time

    # ── Display table ───────────────────────────────────────────────────────
    print_table(results, show_closed=args.show_closed)
    print(f"  Scan completed in {elapsed:.2f} seconds.\n")

    # ── Save output ─────────────────────────────────────────────────────────
    if args.output:
        ext = args.output.rsplit(".", 1)[-1].lower()
        if ext == "json":
            save_json(results, args.output)
        elif ext == "csv":
            save_csv(results, args.output)
        else:
            # Default to JSON if extension is unrecognised
            print(f"  [!] Unknown extension '.{ext}', saving as JSON.")
            save_json(results, args.output)


if __name__ == "__main__":
    main()
