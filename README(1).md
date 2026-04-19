# ReconX — Penetration Testing Reconnaissance Toolkit

A modular, Python-based penetration testing toolkit covering three core phases of a real-world offensive security engagement — network reconnaissance, web enumeration, and password attacks.

Built and tested against DVWA (Damn Vulnerable Web App) running on Docker.

> **Legal Disclaimer:** Only use against systems you own or have explicit written permission to test. Unauthorized access is illegal under the IT Act 2000 (India) and equivalent laws worldwide.

---

## Toolkit Overview

```
reconx/
├── reconx_day1.py   → Phase 1: Network Reconnaissance
├── reconx_day2.py   → Phase 2: Web Enumeration
├── reconx_day3.py   → Phase 3: Password Attacks
├── README_Day1.md   → Phase 1 documentation
├── README_Day2.md   → Phase 2 documentation
└── README_Day3.md   → Phase 3 documentation
```

---

## Phase 1 — Network Reconnaissance

**File:** `reconx_day1.py`

Performs full network-level reconnaissance against a target IP or hostname.

| Feature | Details |
|---|---|
| Port Scanning | Threaded TCP scan — 65,000 ports in ~3 seconds |
| Service Detection | Identifies 25+ services by port number |
| Banner Grabbing | Reads service greeting messages to reveal software versions |
| OS Fingerprinting | TTL-based OS detection (Linux ~64, Windows ~128) |
| Report | Timestamped `.txt` report of all findings |

```bash
python3 reconx_day1.py -t localhost -p 1-65000
```

**Sample findings on DVWA:**
```
[+] TTL=64 → Likely OS: Linux / Unix / macOS
[OPEN]  Port 80    HTTP    | Banner: Apache/2.4.25 (Debian)
[OPEN]  Port 8080  HTTP-Alt| Banner: Apache/2.4.25 (Debian)
[*] Scan complete in 3s — 2 open port(s) found
```

→ [Full Phase 1 Documentation](README_Day1.md)

---

## Phase 2 — Web Enumeration

**File:** `reconx_day2.py`

Discovers hidden content and fingerprints the technology stack of a web target.

| Feature | Details |
|---|---|
| Tech Fingerprinting | Server, language, CMS, framework from headers + HTML |
| Directory Brute Force | Tests 100+ paths — finds hidden files, backups, admin panels |
| Admin Panel Detection | Targeted hunt for login pages and control panels |
| Security Header Audit | Flags missing CSP, HSTS, X-Frame-Options, and more |
| Report | Timestamped `.txt` report of all findings |

```bash
python3 reconx_day2.py -u http://localhost:8080
```

**Sample findings on DVWA:**
```
[+] Web Server:    Apache/2.4.25 (Debian)
[!] Apache 2.4.25 is outdated — check CVE database
[+] Language:      PHP (PHPSESSID cookie detected)
[+] CMS Detected:  DVWA
[!] Missing headers: CSP, X-Frame-Options, X-Content-Type-Options, HSTS

[FOUND ] 200 | /login.php       ← active login page
[REDIR ] 302 | /phpinfo.php     ← PHP config page behind login
[FORBID] 403 | /.htpasswd       ← password file exists
[FORBID] 403 | /.htaccess       ← server config exists
[FOUND ] 200 | /robots.txt      ← potential path disclosure
[FOUND ] 200 | /CHANGELOG.md    ← version disclosure
```

→ [Full Phase 2 Documentation](README_Day2.md)

---

## Phase 3 — Password Attacks

**File:** `reconx_day3.py`

Performs intelligent login form analysis followed by automated credential testing.

| Feature | Details |
|---|---|
| Form Analyser | Auto-detects field names, CSRF tokens, and submit structure |
| Failure Fingerprinting | Learns what a failed login looks like to detect success accurately |
| Default Credentials | Tests 50+ real-world default pairs (admin/admin, root/root, etc.) |
| Wordlist Brute Force | Threaded password attacks with configurable speed and delay |
| Auto-Stop | All threads halt immediately when valid credentials are found |
| Report | Timestamped `.txt` report of all findings |

```bash
python3 reconx_day3.py -u http://localhost:8080/login.php -U admin
```

**Key learning — CSRF protection in action:**
DVWA's login page uses a rotating CSRF token (detected as `user_token`). The scanner correctly identified and handled this — fetching a fresh token before every request. This is exactly why brute forcing CSRF-protected forms is significantly harder in practice and why CSRF tokens are an effective defence against automated attacks.

→ [Full Phase 3 Documentation](README_Day3.md)

---

## How a Real Pentest Uses These Phases

```
Phase 1 — Network Recon
    └─ Found: Apache/2.4.25 on port 80 and 8080
              ↓
Phase 2 — Web Enumeration
    └─ Found: PHP backend, login.php, .htpasswd exists,
              missing all security headers, DVWA CMS
              ↓
Phase 3 — Password Attacks
    └─ Target: login.php with admin username
       CSRF token detected and handled per request
       Result: Brute force mitigated by CSRF rotation
```

This mirrors the real penetration testing methodology:
**Reconnaissance → Enumeration → Exploitation**

---

## Requirements

```bash
# Phase 1 — no external dependencies
python3 --version  # Python 3.6+

# Phase 2 and 3
pip3 install requests beautifulsoup4
# or
sudo apt install python3-requests python3-bs4
```

## Test Environment Setup

```bash
# Run DVWA locally using Docker
sudo docker run -d -p 8080:80 vulnerables/web-dvwa

# Verify it's running
sudo docker ps
```

Then visit `http://localhost:8080` — login with `admin:password` and set security level to Low for testing.

---

## Skills Demonstrated

- Python scripting (threading, sockets, HTTP requests, HTML parsing)
- Network reconnaissance and port scanning concepts
- Web application fingerprinting and directory enumeration
- Password attack methodology and CSRF token handling
- Offensive security tooling and penetration testing workflow
- Technical documentation and security reporting

---

## Author

**Jay Sharma** — Cybersecurity Analyst | Mumbai, India

[GitHub](https://github.com/jay-sharma-sec) · [LinkedIn](https://www.linkedin.com/in/jay-sharma-cybersecurity-analyst) · jaysharma4626@gmail.com
