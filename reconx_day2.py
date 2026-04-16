#!/usr/bin/env python3
"""
ReconX — Day 2: Web Enumeration
Author: Jay Sharma (github.com/jay-sharma-sec)
Description: Phase 2 of ReconX — directory brute forcing, technology
             fingerprinting, and admin panel detection.
"""

import requests
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

def banner():
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════╗
║   ReconX — Web Enumeration              ║
║   Phase 2: Dirs + Tech + Admin Hunt     ║
║   github.com/jay-sharma-sec             ║
╚══════════════════════════════════════════╝{RESET}
""")

# ─────────────────────────────────────────────────────────────────────────────
# WORDLISTS
# Why wordlists: Instead of randomly guessing, we use lists of names that
# commonly appear on web servers based on years of real-world pentesting data.
# Real tools use wordlists with millions of entries — ours covers the most
# impactful common ones to keep it fast and educational.
# ─────────────────────────────────────────────────────────────────────────────

# Common directories and files found on web servers
COMMON_DIRS = [
    # Admin and control panels
    "admin", "administrator", "admin.php", "admin.html", "adminpanel",
    "admin/login", "admin/dashboard", "admin/index.php", "controlpanel",
    "cpanel", "manager", "management", "moderator", "webadmin",

    # Authentication pages
    "login", "login.php", "login.html", "signin", "signup", "register",
    "logout", "auth", "authentication", "user", "users", "account",

    # Common web app directories
    "dashboard", "panel", "portal", "console", "backend", "cms",
    "wp-admin", "wp-login.php", "wordpress", "joomla", "drupal",

    # API endpoints
    "api", "api/v1", "api/v2", "rest", "graphql", "swagger",
    "api/users", "api/admin", "api/login",

    # Configuration and sensitive files
    ".env", "config.php", "config.yml", "config.json", "settings.php",
    "configuration.php", "database.php", "db.php", "conn.php",
    ".htaccess", ".htpasswd", "web.config", "phpinfo.php",

    # Backup files — often left accidentally by developers
    "backup", "backup.zip", "backup.sql", "backup.tar.gz",
    "db_backup.sql", "site_backup.zip", "old", "bak",
    "index.php.bak", "config.php.bak",

    # Information disclosure
    "robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt",
    "readme.txt", "README.md", "CHANGELOG.md", "LICENSE",
    "server-status", "server-info",

    # Upload directories
    "upload", "uploads", "files", "file", "images", "img",
    "media", "static", "assets", "content",

    # Common application paths
    "test", "tests", "dev", "development", "staging", "demo",
    "temp", "tmp", "cache", "logs", "log", "error_log",

    # PHP specific
    "phpmyadmin", "pma", "myadmin", "mysql", "mysqladmin",
    "php", "include", "includes", "lib", "library",

    # Shell and exploit indicators
    "shell.php", "cmd.php", "c99.php", "r57.php", "webshell.php",
]

# Specifically targeted admin panel paths
ADMIN_PATHS = [
    "admin", "admin/", "admin/login", "admin/login.php",
    "administrator", "administrator/", "administrator/login",
    "adminpanel", "admin_panel", "admin-panel",
    "backend", "backend/login", "backend/admin",
    "controlpanel", "control_panel", "cpanel",
    "manager", "manage", "management",
    "wp-admin", "wp-admin/", "wp-login.php",
    "joomla/administrator", "index.php/administrator",
    "user/login", "users/login", "account/login",
    "auth/login", "login", "signin",
    "portal", "portal/login", "dashboard",
    "console", "console/login",
    "phpmyadmin", "pma", "myadmin",
    "webmin", "plesk", "directadmin",
]

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Technology Fingerprinting
# Why: Before brute forcing, we identify what technology the site uses.
#      This tells us which wordlist entries are relevant — no point looking
#      for wp-admin if the site isn't WordPress.
#      We fingerprint by reading response headers and page content.
# ─────────────────────────────────────────────────────────────────────────────
def fingerprint_technology(url):
    """
    Analyse HTTP response headers and page content to identify:
    - Web server (Apache, Nginx, IIS)
    - Programming language (PHP, Python, Ruby)
    - CMS (WordPress, Joomla, Drupal)
    - Frameworks and libraries
    """
    print(f"\n{CYAN}[*] Fingerprinting technology stack...{RESET}")

    findings = []

    try:
        headers = {"User-Agent": "Mozilla/5.0 (ReconX Scanner)"}
        resp = requests.get(url, headers=headers, timeout=8, allow_redirects=True)
        h = resp.headers
        body = resp.text.lower()

        # ── Server header ─────────────────────────────────────────────────
        # The Server header directly reveals the web server and often its version
        if "server" in h:
            server = h["server"]
            print(f"{GREEN}[+] Web Server:     {server}{RESET}")
            findings.append(f"Web Server: {server}")

            # Flag outdated versions
            if "apache/2.4.25" in server.lower():
                print(f"{RED}[!] Apache 2.4.25 is outdated — check CVE database{RESET}")
                findings.append("WARNING: Outdated Apache version detected")
            if "nginx/1.1" in server.lower():
                print(f"{RED}[!] Old Nginx version detected{RESET}")

        # ── X-Powered-By header ───────────────────────────────────────────
        # Reveals the backend language — PHP, ASP.NET etc.
        # Security-conscious admins disable this header — its presence is
        # itself a misconfiguration
        if "x-powered-by" in h:
            powered = h["x-powered-by"]
            print(f"{GREEN}[+] Powered By:     {powered}{RESET}")
            findings.append(f"Powered By: {powered}")

        # ── Cookie analysis ───────────────────────────────────────────────
        # Cookie names reveal backend technology
        if "set-cookie" in h:
            cookie = h["set-cookie"]
            if "phpsessid" in cookie.lower():
                print(f"{GREEN}[+] Language:       PHP (PHPSESSID cookie detected){RESET}")
                findings.append("Language: PHP")
            elif "jsessionid" in cookie.lower():
                print(f"{GREEN}[+] Language:       Java (JSESSIONID cookie detected){RESET}")
                findings.append("Language: Java")
            elif "asp.net_sessionid" in cookie.lower():
                print(f"{GREEN}[+] Language:       ASP.NET{RESET}")
                findings.append("Language: ASP.NET")

        # ── Security headers check ────────────────────────────────────────
        security_headers = {
            "content-security-policy": "CSP",
            "x-frame-options": "X-Frame-Options",
            "x-content-type-options": "X-Content-Type-Options",
            "strict-transport-security": "HSTS",
        }
        missing = []
        for header, name in security_headers.items():
            if header not in {k.lower() for k in h.keys()}:
                missing.append(name)

        if missing:
            print(f"{YELLOW}[!] Missing security headers: {', '.join(missing)}{RESET}")
            findings.append(f"Missing headers: {', '.join(missing)}")

        # ── CMS Detection from page body ──────────────────────────────────
        # CMS platforms leave fingerprints in page HTML
        cms_signatures = {
            "wordpress":  ["wp-content", "wp-includes", "wordpress"],
            "joomla":     ["joomla", "/components/com_", "mosConfig"],
            "drupal":     ["drupal", "sites/default/files", "drupal.js"],
            "magento":    ["magento", "mage/cookies", "skin/frontend"],
            "shopify":    ["shopify", "cdn.shopify.com"],
            "dvwa":       ["damn vulnerable web application", "dvwa"],
        }

        for cms, signatures in cms_signatures.items():
            if any(sig in body for sig in signatures):
                print(f"{GREEN}[+] CMS Detected:   {cms.upper()}{RESET}")
                findings.append(f"CMS: {cms.upper()}")

        # ── Framework detection ───────────────────────────────────────────
        framework_signatures = {
            "Laravel":    ["laravel_session", "laravel"],
            "Django":     ["csrfmiddlewaretoken", "django"],
            "Rails":      ["_rails_", "authenticity_token"],
            "Express.js": ["express", "x-powered-by: express"],
        }

        for framework, signatures in framework_signatures.items():
            if any(sig in body for sig in signatures):
                print(f"{GREEN}[+] Framework:      {framework}{RESET}")
                findings.append(f"Framework: {framework}")

    except requests.RequestException as e:
        print(f"{RED}[-] Fingerprinting failed: {e}{RESET}")

    return findings

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Directory Brute Forcing
# Why: We systematically request every path in our wordlist.
#      HTTP status codes tell us what exists:
#      200 = page exists and is accessible  ← interesting
#      301/302 = redirect (page exists)     ← interesting
#      403 = forbidden (exists but blocked) ← very interesting
#      404 = not found                      ← skip
#      500 = server error (might be vuln)   ← interesting
# ─────────────────────────────────────────────────────────────────────────────

found_paths = []
dir_lock = threading.Lock()

def check_path(base_url, path, interesting_codes):
    """
    Request a single path and record it if the status code is interesting.
    The status code is the key signal — we don't need to read the full page.
    """
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        headers = {"User-Agent": "Mozilla/5.0 (ReconX Scanner)"}
        resp = requests.get(url, headers=headers, timeout=5,
                          allow_redirects=False)
        code = resp.status_code

        if code in interesting_codes:
            # Colour code by status
            if code == 200:
                colour = GREEN
                label  = "FOUND "
            elif code in (301, 302):
                colour = CYAN
                label  = "REDIR "
            elif code == 403:
                colour = YELLOW
                label  = "FORBID"
            else:
                colour = RED
                label  = f"  {code} "

            size = len(resp.content)
            print(f"{colour}[{label}] {code} | {url:<60} | Size: {size}B{RESET}")

            with dir_lock:
                found_paths.append({
                    "url":    url,
                    "status": code,
                    "size":   size,
                    "path":   path,
                })

    except requests.RequestException:
        pass

def threaded_dir_scan(base_url, wordlist, max_threads=50,
                      interesting_codes=(200, 201, 301, 302, 403, 500)):
    """
    Distribute directory checks across threads using a queue.
    Same threading concept as Day 1 — many workers, one shared todo list.
    """
    queue = Queue()
    for path in wordlist:
        queue.put(path)

    def worker():
        while not queue.empty():
            path = queue.get()
            check_path(base_url, path, interesting_codes)
            queue.task_done()

    threads = []
    for _ in range(min(max_threads, len(wordlist))):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Admin Panel Hunter
# Why: Admin panels are the highest-value targets. If an attacker can reach
#      the admin login page, they can attempt brute force or credential
#      stuffing attacks. We use a targeted list of known admin paths.
# ─────────────────────────────────────────────────────────────────────────────
def hunt_admin_panels(base_url):
    """
    Specifically scan for admin and login pages using a targeted wordlist.
    Runs separately from general directory scan so results are clearly grouped.
    """
    print(f"\n{CYAN}[*] Hunting for admin panels and login pages...{RESET}")
    admin_found = []

    for path in ADMIN_PATHS:
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            headers = {"User-Agent": "Mozilla/5.0 (ReconX Scanner)"}
            resp = requests.get(url, headers=headers, timeout=5,
                              allow_redirects=True)
            code = resp.status_code
            body = resp.text.lower()

            # Check if it looks like a login page
            login_indicators = [
                "login", "password", "username", "sign in",
                "log in", "email", "authenticate"
            ]
            is_login = any(indicator in body for indicator in login_indicators)

            if code == 200:
                label = f"{GREEN}[ADMIN PANEL FOUND]{RESET}"
                if is_login:
                    label += f" {RED}← LOGIN PAGE{RESET}"
                print(f"{label} {url}")
                admin_found.append({"url": url, "status": code,
                                   "is_login": is_login})

            elif code in (301, 302):
                location = resp.headers.get("location", "")
                print(f"{CYAN}[REDIRECT] {url} → {location}{RESET}")
                admin_found.append({"url": url, "status": code,
                                   "is_login": False})

            elif code == 403:
                print(f"{YELLOW}[FORBIDDEN] {url} — exists but access denied{RESET}")
                admin_found.append({"url": url, "status": 403,
                                   "is_login": False})

        except requests.RequestException:
            pass

    if not admin_found:
        print(f"{GREEN}[OK] No admin panels found.{RESET}")

    return admin_found

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Save Report
# ─────────────────────────────────────────────────────────────────────────────
def save_report(target, tech_findings, admin_findings):
    """Save all Day 2 findings to a timestamped report file."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"reconx_day2_report_{timestamp}.txt"

    with open(filename, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("ReconX — Web Enumeration Report\n")
        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Target: {target}\n\n")

        f.write("-" * 60 + "\n")
        f.write("TECHNOLOGY FINGERPRINT\n")
        f.write("-" * 60 + "\n")
        for finding in tech_findings:
            f.write(f"  {finding}\n")

        f.write("\n" + "-" * 60 + "\n")
        f.write("DIRECTORIES FOUND\n")
        f.write("-" * 60 + "\n")
        for entry in sorted(found_paths, key=lambda x: x["status"]):
            f.write(f"  [{entry['status']}] {entry['url']} ({entry['size']}B)\n")

        f.write("\n" + "-" * 60 + "\n")
        f.write("ADMIN PANELS\n")
        f.write("-" * 60 + "\n")
        for entry in admin_findings:
            login_tag = " ← LOGIN PAGE" if entry.get("is_login") else ""
            f.write(f"  [{entry['status']}] {entry['url']}{login_tag}\n")

        f.write("\n" + "=" * 60 + "\n")
        f.write("Always test only on targets you own or have permission to test.\n")

    print(f"\n{GREEN}[+] Report saved: {filename}{RESET}")
    return filename

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="ReconX Phase 2 — Web Enumeration",
        epilog="Example: python3 reconx_day2.py -u http://localhost:8080"
    )
    parser.add_argument("-u", "--url",       required=True,
                        help="Target URL (e.g. http://localhost:8080)")
    parser.add_argument("--threads",         default=50, type=int,
                        help="Number of threads (default: 50)")
    parser.add_argument("--no-fingerprint",  action="store_true",
                        help="Skip technology fingerprinting")
    parser.add_argument("--no-admin",        action="store_true",
                        help="Skip admin panel hunting")
    parser.add_argument("--no-report",       action="store_true",
                        help="Skip saving report")

    args   = parser.parse_args()
    target = args.url.rstrip("/")

    banner()
    print(f"{CYAN}[*] Target: {target}{RESET}")

    # Step 1 — Fingerprint
    tech_findings = []
    if not args.no_fingerprint:
        tech_findings = fingerprint_technology(target)

    # Step 2 — Directory brute force
    print(f"\n{CYAN}[*] Starting directory brute force ({len(COMMON_DIRS)} paths)...{RESET}\n")
    start_time = datetime.datetime.now()
    threaded_dir_scan(target, COMMON_DIRS, args.threads)
    elapsed = (datetime.datetime.now() - start_time).seconds
    print(f"\n{CYAN}[*] Directory scan complete in {elapsed}s — "
          f"{len(found_paths)} path(s) found{RESET}")

    # Step 3 — Admin panel hunt
    admin_findings = []
    if not args.no_admin:
        admin_findings = hunt_admin_panels(target)

    # Step 4 — Report
    if not args.no_report:
        save_report(target, tech_findings, admin_findings)

if __name__ == "__main__":
    main()
