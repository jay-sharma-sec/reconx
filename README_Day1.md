# ReconX — Phase 1: Network Reconnaissance

A Python-based network reconnaissance tool that performs port scanning, service detection, banner grabbing, and OS fingerprinting. Phase 1 of the ReconX penetration testing toolkit.

## What It Does

| Feature | Description |
|---|---|
| Port Scanning | Scans any port range using multithreading — 65,000 ports in ~3 seconds |
| Service Detection | Identifies services on open ports (HTTP, SSH, FTP, MySQL, RDP, and 20+ more) |
| Banner Grabbing | Connects to open ports and reads the service greeting — reveals software versions |
| OS Fingerprinting | Uses TTL values from ping responses to guess the target OS |
| Report Generation | Saves all findings to a timestamped `.txt` report |

## How It Works

### Port Scanning with Threading
Instead of checking ports one by one (slow), the scanner spawns 100 worker threads simultaneously. Each thread grabs a port from a shared queue and attempts a TCP connection. This is the same concept used by tools like Nmap.

```
Sequential scan of 1000 ports @ 1s timeout = ~1000 seconds
Threaded scan of 1000 ports @ 100 threads  = ~10 seconds
```

### Banner Grabbing
When a port is open, the scanner connects and reads the first response — called a "banner". This often reveals the exact software and version running:

```
Port 80 → Apache/2.4.25 (Debian)   ← exact version, check CVEs
Port 22 → SSH-2.0-OpenSSH_8.2p1    ← SSH version
Port 21 → 220 FTP server ready      ← FTP service info
```

### OS Fingerprinting via TTL
Different operating systems use different default TTL values in network packets:

| TTL Value | Likely OS |
|---|---|
| ~64 | Linux / Unix / macOS |
| ~128 | Windows |
| ~255 | Network Device (Router/Switch) |

## Requirements

No external libraries required — uses Python standard library only.

```bash
python3 --version  # Requires Python 3.6+
```

## Usage

```bash
python3 reconx_day1.py -t <target> -p <port-range>
```

### Examples

```bash
# Scan common ports on localhost
python3 reconx_day1.py -t localhost -p 1-1024

# Full scan — all 65000 ports
python3 reconx_day1.py -t localhost -p 1-65000

# Custom thread count
python3 reconx_day1.py -t 192.168.1.1 -p 1-1024 --threads 200

# Skip OS fingerprinting
python3 reconx_day1.py -t localhost -p 1-1024 --no-os

# Skip saving report
python3 reconx_day1.py -t localhost -p 1-1024 --no-report
```

### Sample Output

```
╔══════════════════════════════════════════╗
║   ReconX — Network Reconnaissance       ║
║   Phase 1: Port Scan + Banner Grab      ║
║   github.com/jay-sharma-sec             ║
╚══════════════════════════════════════════╝

[+] Resolved localhost → 127.0.0.1
[+] TTL=64 → Likely OS: Linux / Unix / macOS

[*] Scanning ports 1-65000 on 127.0.0.1...
[*] Using 100 threads

[OPEN]  Port 80     HTTP    | Banner: HTTP/1.1 302 Found ... Server: Apache/2.4.25 (Debian)
[OPEN]  Port 8080   HTTP-Alt| Banner: HTTP/1.1 302 Found ... Server: Apache/2.4.25 (Debian)
[OPEN]  Port 3306   MySQL   |

[*] Scan complete in 3s — 3 open port(s) found
[+] Report saved: reconx_report_localhost_20260415_120000.txt
```

## Real World Application

The intelligence gathered in Phase 1 directly feeds into the next attack phases:

- **Apache/2.4.25 found** → Search CVE database for known exploits
- **Port 3306 (MySQL) open** → Attempt default credentials in Phase 3
- **SSH on port 22** → Password brute force target in Phase 3
- **OS = Linux** → Use Linux-specific exploits and paths

## Legal Disclaimer

This tool is intended for **educational purposes and authorized penetration testing only**. Only use against targets you own or have explicit written permission to test. Unauthorized scanning is illegal.

## Author

**Jay Sharma** — [github.com/jay-sharma-sec](https://github.com/jay-sharma-sec) | [LinkedIn](https://www.linkedin.com/in/jay-sharma-cybersecurity-analyst)

---

*Part of the [ReconX](https://github.com/jay-sharma-sec/reconx) penetration testing toolkit.*
