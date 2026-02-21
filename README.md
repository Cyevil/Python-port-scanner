# 🔍 portscanner.py

A production-ready, concurrent TCP port scanner written in pure Python. No third-party dependencies, no external frameworks — just the standard library.

---

## Features

- **Async concurrency** via `asyncio` — scans hundreds of ports simultaneously
- **Banner grabbing** — sends minimal probes to identify what's running on open ports
- **Flexible port specification** — ranges, lists, or mixed (e.g. `22,80-90,443`)
- **Service name detection** — built-in lookup table for 60+ well-known ports with `socket.getservbyport` fallback
- **Port state classification** — `open`, `closed`, or `filtered`
- **Clean table output** — aligned columns for port, state, service, and banner
- **Export support** — save results as JSON or CSV
- **Verbose / live mode** — print open ports in real time as they're found
- **Timeout control** — tune aggressiveness vs. accuracy

---

## Requirements

- Python **3.7+** (uses `asyncio.run()` and `asyncio.open_connection()`)
- No pip installs needed — only standard library modules are used:
  `asyncio`, `socket`, `argparse`, `csv`, `json`, `threading`, `sys`, `time`

---

## Installation

```bash
# Clone or download the script
git clone https://github.com/yourname/portscanner.git
cd portscanner

# Make it executable (Linux / macOS)
chmod +x portscanner.py
```

No virtual environment or `pip install` required.

---

## Usage

```
python portscanner.py -t <TARGET> [options]
```

### All flags

| Flag | Long form | Type | Default | Description |
|---|---|---|---|---|
| `-t` | `--target` | string | *required* | IP address or hostname to scan |
| `-p` | `--ports` | string | `1-1024` | Port specification (see formats below) |
| `-T` | `--timeout` | float | `1.0` | Connection timeout in seconds |
| `-o` | `--output` | string | — | Save results to file (`.json` or `.csv`) |
| `-v` | `--verbose` | flag | off | Print open ports live as they are discovered |
| | `--show-closed` | flag | off | Include closed/filtered ports in the output table |

### Port specification formats

| Format | Example | Meaning |
|---|---|---|
| Single port | `80` | Port 80 only |
| Range | `1-1024` | Ports 1 through 1024 |
| Comma list | `22,80,443` | Exactly those three ports |
| Mixed | `22,80-90,443,8000-8100` | Combination of singles and ranges |

Duplicates are automatically removed and ports are always scanned in order.

---

## Example Commands

```bash
# Scan the default common port range (1–1024)
python portscanner.py -t example.com

# Scan a specific list of ports
python portscanner.py -t 192.168.1.1 -p 22,80,443,3306,5432

# Scan with a longer timeout for slow or remote hosts
python portscanner.py -t 10.0.0.50 -p 1-1024 -T 3

# Verbose mode: see open ports printed in real time
python portscanner.py -t 192.168.1.1 -p 1-1024 -v

# Save results as JSON
python portscanner.py -t scanme.nmap.org -p 1-1000 -o results.json

# Save results as CSV
python portscanner.py -t 10.0.0.1 -p 1-65535 -T 0.5 -o report.csv

# Full 65535-port scan (fast — ~1–2 min with default timeout)
python portscanner.py -t 192.168.1.100 -p 1-65535 -T 0.5

# Show all ports including closed ones in the table
python portscanner.py -t 192.168.1.1 -p 1-100 --show-closed

# Combine flags
python portscanner.py -t 10.10.10.5 -p 22,80-90,443,8000-8080 -T 2 -v -o scan.json
```

---

## Sample Output

```
════════════════════════════════════════════════════════════════════════════════
  Port Scanner  |  2025-07-18 14:32:07
════════════════════════════════════════════════════════════════════════════════
  Target  : scanme.nmap.org (45.33.32.156)
  Ports   : 1024 port(s)  [1–1024]
  Timeout : 1.0s  |  Concurrency: 500 max
════════════════════════════════════════════════════════════════════════════════

────────────────────────────────────────────────────────────────────────────────
PORT     STATE      SERVICE          BANNER
────────────────────────────────────────────────────────────────────────────────
  22     open       ssh              SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
  80     open       http             HTTP/1.1 200 OK Date: Fri, 18 Jul 2025 12:3…
  443    open       https
────────────────────────────────────────────────────────────────────────────────
  Summary: 3 open  |  1018 closed  |  3 filtered

  Scan completed in 4.83 seconds.
```

---

## JSON Output Format

When saving with `-o results.json`, the file looks like:

```json
{
  "scan_results": [
    {
      "port": 22,
      "state": "open",
      "service": "ssh",
      "banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"
    },
    {
      "port": 80,
      "state": "open",
      "service": "http",
      "banner": "HTTP/1.1 200 OK Date: Fri, 18 Jul 2025 ..."
    },
    {
      "port": 81,
      "state": "closed",
      "service": "unknown",
      "banner": ""
    }
  ]
}
```

## CSV Output Format

When saving with `-o results.csv`:

```
port,state,service,banner
22,open,ssh,SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
80,open,http,HTTP/1.1 200 OK ...
81,closed,unknown,
```

---

## How Concurrency Works

The scanner uses Python's `asyncio` event loop — **not** threads — for concurrency. Here's the flow:

```
asyncio.run(run_scan(...))
         │
         ├─ creates asyncio.Semaphore(500)
         │
         ├─ builds a list of coroutines: [scan_port(port_1), scan_port(port_2), ...]
         │
         └─ asyncio.gather(*tasks)
                  │
                  ├─ scan_port(22)  ─── asyncio.open_connection() ──► TCP handshake
                  ├─ scan_port(80)  ─── asyncio.open_connection() ──► TCP handshake
                  ├─ scan_port(443) ─── asyncio.open_connection() ──► TCP handshake
                  └─ ... up to 500 simultaneously (semaphore-limited)
```

**Why `asyncio` instead of threads?**

- Thread creation has overhead; `asyncio` coroutines are extremely lightweight (~1 KB each).
- Networking is I/O-bound — while one coroutine waits for a TCP response, the event loop runs others. No GIL contention.
- The `asyncio.Semaphore(500)` prevents opening more than 500 sockets at once, protecting against OS file-descriptor exhaustion (`ulimit -n`).
- `asyncio.gather()` with `return_exceptions=True` ensures one failing coroutine cannot cancel the rest.

**Why is it fast?** A 1024-port scan with 1s timeout completes in roughly 2–6 seconds because almost all port coroutines are waiting for their TCP timeout simultaneously, not sequentially.

---

## Port State Definitions

| State | Meaning |
|---|---|
| `open` | TCP connection accepted — something is listening |
| `closed` | Connection actively refused (`ConnectionRefusedError`) — port is reachable but nothing is listening |
| `filtered` | No response within timeout — likely a firewall is silently dropping packets |

---

## Banner Grabbing

For every open port, the scanner sends two probes in order and returns the first non-empty response:

1. `HEAD / HTTP/1.0\r\nHost: target\r\n\r\n` — works for HTTP, HTTPS, and many web-adjacent services.
2. `\r\n` — a generic newline; services like FTP, SMTP, SSH, and Telnet typically send their banner immediately on connection and respond to this.

Banners are decoded as UTF-8 (invalid bytes replaced with `?`), whitespace is collapsed, and the result is capped at 200 characters.

---

## Performance Tuning

| Scenario | Recommended settings |
|---|---|
| Fast LAN scan | `-T 0.3` — aggressive timeout for local networks |
| Internet host | `-T 1.0` to `-T 2.0` — allow for latency |
| Slow / filtered host | `-T 3.0` or higher |
| Full 65535-port scan | `-T 0.5 -p 1-65535` — completes in ~2–4 minutes |
| Lower OS fd limit | Edit `MAX_CONCURRENT = 500` in source to `200` or `100` |

Check your OS file-descriptor limit with:

```bash
# Linux / macOS
ulimit -n

# Increase temporarily if needed
ulimit -n 4096
```

---

## Ethical and Legal Notice

> **Only scan hosts and networks you own or have explicit written permission to test.**
>
> Unauthorized port scanning may be illegal under computer misuse laws in your jurisdiction (e.g. the Computer Fraud and Abuse Act in the US, the Computer Misuse Act in the UK). The authors accept no liability for misuse of this tool.

This tool is intended for:
- Network administrators auditing their own infrastructure
- Security professionals with authorized scope
- Students learning about networking and Python concurrency
- CTF / home lab environments

---

## Project Structure

```
portscanner/
├── portscanner.py     # Single-file tool — all logic lives here
└── README.md          # This file
```

### Internal module map

| Function / coroutine | Role |
|---|---|
| `parse_ports(spec)` | Parses port spec strings into a sorted list |
| `get_service_name(port)` | Returns IANA service name for a port number |
| `grab_banner(reader, writer, timeout)` | Sends probes and reads response from open connection |
| `scan_port(host, port, ...)` | Async coroutine: connect → grab banner → classify state |
| `run_scan(host, ports, ...)` | Orchestrates all `scan_port` coroutines with semaphore |
| `print_table(results, ...)` | Renders aligned table to stdout |
| `save_json(results, path)` | Writes `{"scan_results": [...]}` to a `.json` file |
| `save_csv(results, path)` | Writes rows to a `.csv` file |
| `build_parser()` | Defines and returns the `argparse.ArgumentParser` |
| `main()` | CLI entry point: parse args → resolve host → run scan → output |

---

## License

MIT — use freely, modify freely, don't blame us.
