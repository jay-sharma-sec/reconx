#!/usr/bin/env python3
"""
ReconX — Day 1: Network Reconnaissance
Author: Jay Sharma (github.com/jay-sharma-sec)
Description: Phase 1 of ReconX — scans ports, detects services, grabs banners,
             and saves a full reconnaissance report.
"""

import socket
import threading
import argparse
import datetime
from queue import Queue

# ── Colours ──────────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ── Well-known port → service name mapping ───────────────────────────────────
# This is our own lookup table so we don't need external libraries.
# Real tools like Nmap have thousands of these — we cover the most common ones.
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "MS RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    993:  "IMAPS",
    995:  "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9200: "Elasticsearch",
    27017:"MongoDB",
}

def banner():
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════╗
║   ReconX — Network Reconnaissance       ║
║   Phase 1: Port Scan + Banner Grab      ║
║   github.com/jay-sharma-sec             ║
╚══════════════════════════════════════════╝{RESET}
""")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Resolve the target hostname to an IP address
# Why: We need the raw IP to open socket connections. Domain names are
#      human-friendly aliases — the network only understands IPs.
# ─────────────────────────────────────────────────────────────────────────────
def resolve_target(target):
    """Convert a hostname like 'example.com' to its IP address."""
    try:
        ip = socket.gethostbyname(target)
        print(f"{GREEN}[+] Resolved {target} → {ip}{RESET}")
        return ip
    except socket.gaierror:
        print(f"{RED}[-] Could not resolve hostname: {target}{RESET}")
        return None

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Banner grabbing
# Why: When you connect to an open port, many services send a greeting message
#      called a "banner". This often contains the software name and version.
#      Example: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
#      Knowing the version lets attackers look up known CVEs for that version.
# ─────────────────────────────────────────────────────────────────────────────
def grab_banner(ip, port, timeout=2):
    """
    Connect to an open port and read the first response.
    Returns the banner string, or None if nothing is received.
    """
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Some services (like HTTP) need us to send something first
        # before they respond — send a basic HTTP request
        if port in (80, 8080, 8443, 8888):
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")

        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner if banner else None
    except Exception:
        return None

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Port scanning with threading
# Why threading: Scanning ports one by one (sequentially) is very slow —
#      if each connection times out at 1 second, scanning 1000 ports = 1000s.
#      With threading, we scan many ports simultaneously, cutting time to seconds.
#      Think of it like having 100 workers knock on 100 doors at once vs one
#      worker knocking on each door one at a time.
# ─────────────────────────────────────────────────────────────────────────────

# Shared list to store results — threads write here as they find open ports
open_ports = []
# Lock prevents two threads writing to the list at the same moment (race condition)
lock = threading.Lock()

def scan_port(ip, port, timeout=1):
    """
    Try to connect to a single port.
    If the connection succeeds → port is open.
    If it's refused or times out → port is closed/filtered.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # AF_INET = IPv4, SOCK_STREAM = TCP connection
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        # connect_ex returns 0 if connection succeeded, non-zero if failed
        sock.close()

        if result == 0:
            # Port is open — identify service and grab banner
            service = COMMON_PORTS.get(port, "Unknown")
            banner  = grab_banner(ip, port)

            with lock:
                open_ports.append({
                    "port":    port,
                    "service": service,
                    "banner":  banner
                })

            banner_str = f" | Banner: {banner[:60]}" if banner else ""
            print(f"{GREEN}[OPEN]  Port {port:<6} {service:<18}{banner_str}{RESET}")

    except Exception:
        pass

def threaded_scan(ip, port_range, max_threads=100):
    """
    Distribute port scanning across multiple threads using a queue.
    The Queue acts like a todo list — threads grab ports from it
    and scan them until the list is empty.
    """
    queue = Queue()

    # Fill the queue with all ports to scan
    for port in range(port_range[0], port_range[1] + 1):
        queue.put(port)

    def worker():
        while not queue.empty():
            port = queue.get()
            scan_port(ip, port)
            queue.task_done()

    # Spawn threads up to max_threads
    threads = []
    for _ in range(min(max_threads, queue.qsize())):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — OS Fingerprinting (basic TTL-based hint)
# Why: Different operating systems use different default TTL (Time To Live)
#      values in their network packets. By checking the TTL of a ping response
#      we can make an educated guess about the OS.
#      TTL ~64  → Linux/Unix
#      TTL ~128 → Windows
#      TTL ~255 → Network device (router, switch)
# ─────────────────────────────────────────────────────────────────────────────
def os_fingerprint_hint(ip):
    """Use socket TTL to make a basic OS guess."""
    import subprocess
    print(f"\n{CYAN}[*] Attempting basic OS fingerprint...{RESET}")
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", ip],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout

        # Extract TTL value from ping output
        if "ttl=" in output.lower():
            ttl_str = [x for x in output.lower().split() if "ttl=" in x][0]
            ttl = int(ttl_str.split("=")[1])

            if ttl <= 64:
                guess = "Linux / Unix / macOS"
            elif ttl <= 128:
                guess = "Windows"
            else:
                guess = "Network Device (Router/Switch)"

            print(f"{GREEN}[+] TTL={ttl} → Likely OS: {guess}{RESET}")
            return guess, ttl
        else:
            print(f"{YELLOW}[~] Could not determine TTL{RESET}")
            return "Unknown", None
    except Exception as e:
        print(f"{YELLOW}[~] OS fingerprint failed: {e}{RESET}")
        return "Unknown", None

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — Save report
# Why: In real pentesting, everything gets documented. A scan with no report
#      is useless. This saves all findings to a timestamped .txt file.
# ─────────────────────────────────────────────────────────────────────────────
def save_report(target, ip, os_guess, port_range):
    """Write a clean report of all findings to a .txt file."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"reconx_report_{target}_{timestamp}.txt"

    with open(filename, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("ReconX — Network Reconnaissance Report\n")
        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"Target:     {target}\n")
        f.write(f"IP Address: {ip}\n")
        f.write(f"OS Guess:   {os_guess}\n")
        f.write(f"Port Range: {port_range[0]} - {port_range[1]}\n\n")

        f.write("-" * 60 + "\n")
        f.write("OPEN PORTS\n")
        f.write("-" * 60 + "\n")

        if open_ports:
            for entry in sorted(open_ports, key=lambda x: x["port"]):
                f.write(f"\nPort:    {entry['port']}\n")
                f.write(f"Service: {entry['service']}\n")
                if entry["banner"]:
                    f.write(f"Banner:  {entry['banner'][:200]}\n")
        else:
            f.write("No open ports found.\n")

        f.write("\n" + "=" * 60 + "\n")
        f.write("Recon Complete. \n")

    print(f"\n{GREEN}[+] Report saved: {filename}{RESET}")
    return filename

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="ReconX Phase 1 — Network Reconnaissance",
        epilog="Example: python3 reconx_day1.py -t localhost -p 1-1000"
    )
    parser.add_argument("-t", "--target",   required=True, help="Target IP or hostname")
    parser.add_argument("-p", "--ports",    default="1-1024", help="Port range e.g. 1-1024 (default: 1-1024)")
    parser.add_argument("--threads",        default=100, type=int, help="Number of threads (default: 100)")
    parser.add_argument("--no-os",          action="store_true", help="Skip OS fingerprinting")
    parser.add_argument("--no-report",      action="store_true", help="Skip saving report")

    args   = parser.parse_args()
    target = args.target.strip()

    # Parse port range
    try:
        start, end = map(int, args.ports.split("-"))
        port_range = (start, end)
    except ValueError:
        print(f"{RED}[-] Invalid port range. Use format: 1-1024{RESET}")
        return

    banner()

    # Step 1 — Resolve
    ip = resolve_target(target)
    if not ip:
        return

    # Step 2 — OS fingerprint
    os_guess = "Skipped"
    if not args.no_os:
        os_guess, _ = os_fingerprint_hint(ip)

    # Step 3 — Scan
    print(f"\n{CYAN}[*] Scanning ports {port_range[0]}-{port_range[1]} on {ip}...{RESET}")
    print(f"{CYAN}[*] Using {args.threads} threads{RESET}\n")

    start_time = datetime.datetime.now()
    threaded_scan(ip, port_range, args.threads)
    elapsed = (datetime.datetime.now() - start_time).seconds

    print(f"\n{CYAN}[*] Scan complete in {elapsed}s — {len(open_ports)} open port(s) found{RESET}")

    # Step 4 — Report
    if not args.no_report:
        save_report(target, ip, os_guess, port_range)

if __name__ == "__main__":
    main()
