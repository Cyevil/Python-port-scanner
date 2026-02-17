#!/usr/bin/env python3

import socket
import argparse
import concurrent.futures
import json
import csv
import sys
from datetime import datetime

# ----------------------------
# Utility Functions
# ----------------------------

def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Unable to resolve target: {target}")
        sys.exit(1)


def parse_ports(port_input):
    ports = []
    if "-" in port_input:
        start, end = port_input.split("-")
        ports = range(int(start), int(end) + 1)
    else:
        ports = [int(p.strip()) for p in port_input.split(",")]
    return ports


def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "unknown"


# ----------------------------
# Core Scan Logic
# ----------------------------

def scan_port(target_ip, port, timeout):
    result = {
        "port": port,
        "state": "closed",
        "service": "",
        "banner": ""
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            connection = sock.connect_ex((target_ip, port))
            if connection == 0:
                result["state"] = "open"
                result["service"] = get_service_name(port)

                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                    result["banner"] = banner
                except:
                    result["banner"] = ""
            else:
                result["state"] = "closed"

        except Exception:
            result["state"] = "filtered"

    return result


# ----------------------------
# Output Functions
# ----------------------------

def print_results(results):
    print("\n--- Scan Results ---")
    print(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<15}BANNER")
    print("-" * 60)

    for r in results:
        if r["state"] == "open":
            print(f"{r['port']:<10}{r['state']:<10}{r['service']:<15}{r['banner'][:50]}")


def save_output(results, filename):
    if filename.endswith(".json"):
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
    elif filename.endswith(".csv"):
        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["port", "state", "service", "banner"])
            writer.writeheader()
            writer.writerows(results)
    else:
        print("[!] Unsupported file format. Use .json or .csv")


# ----------------------------
# Main Execution
# ----------------------------

def main():
    parser = argparse.ArgumentParser(description="Multi-threaded TCP Port Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g., 1-1000 or 22,80,443)")
    parser.add_argument("-T", "--timeout", type=float, default=1.0, help="Connection timeout (seconds)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Number of concurrent threads")
    parser.add_argument("-o", "--output", help="Save results to file (.json or .csv)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    print(f"\n[+] Resolving target {args.target}")
    target_ip = resolve_target(args.target)
    print(f"[+] Target IP: {target_ip}")

    ports = parse_ports(args.ports)
    results = []

    print(f"[+] Starting scan at {datetime.now()}")
    print(f"[+] Scanning {len(list(ports))} ports with {args.workers} threads\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_port = {
            executor.submit(scan_port, target_ip, port, args.timeout): port
            for port in ports
        }

        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            results.append(result)

            if args.verbose and result["state"] == "open":
                print(f"[OPEN] Port {result['port']} ({result['service']})")

    results.sort(key=lambda x: x["port"])
    print_results(results)

    if args.output:
        save_output(results, args.output)
        print(f"\n[+] Results saved to {args.output}")

    print(f"\n[+] Scan completed at {datetime.now()}")


if __name__ == "__main__":
    main()
