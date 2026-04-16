# ReconX — Phase 2: Web Enumeration

A Python-based web enumeration tool that performs directory brute forcing, technology fingerprinting, and admin panel detection. Phase 2 of the ReconX penetration testing toolkit.

## What It Does

| Feature | Description |
|---|---|
| Technology Fingerprinting | Identifies web server, language, CMS, and framework from headers and page content |
| Directory Brute Forcing | Tests 100+ common paths to discover hidden pages, files, and directories |
| Admin Panel Detection | Hunts specifically for login pages and admin interfaces |
| Security Header Audit | Flags missing security headers (CSP, HSTS, X-Frame-Options, etc.) |
| Report Generation | Saves all findings to a timestamped `.txt` report |

## How It Works

### Technology Fingerprinting
Before brute forcing, the scanner silently reads HTTP response headers to extract intelligence without triggering alerts:

```
Server: Apache/2.4.25 (Debian)   → Web server + version (check CVEs)
X-Powered-By: PHP/7.0            → Backend language
Set-Cookie: PHPSESSID=...        → Confirms PHP backend
Page body: "wp-content"          → WordPress CMS detected
```

### Directory Brute Forcing
HTTP status codes are the signal — no need to read the full page:

| Status Code | Meaning | Priority |
|---|---|---|
| `200 OK` | Page exists, fully accessible | Highest |
| `403 Forbidden` | Page exists but blocked | High — something is there |
| `301/302 Redirect` | Page exists, redirects somewhere | Medium — follow the trail |
| `404 Not Found` | Nothing there | Ignored |
| `500 Server Error` | Crashed — might indicate vulnerability | High |

### Admin Panel Detection
Uses a targeted wordlist of known admin paths and reads page content for login indicators — words like "password", "username", "authenticate" — so it confirms it's actually a login page, not just a named path.

## Requirements

```bash
pip3 install requests
# or
sudo apt install python3-requests
```

## Usage

```bash
python3 reconx_day2.py -u <target_url>
```

### Examples

```bash
# Full scan
python3 reconx_day2.py -u http://localhost:8080

# Custom thread count
python3 reconx_day2.py -u http://localhost:8080 --threads 30

# Skip fingerprinting
python3 reconx_day2.py -u http://localhost:8080 --no-fingerprint

# Skip admin hunting
python3 reconx_day2.py -u http://localhost:8080 --no-admin
```

### Sample Output

```
╔══════════════════════════════════════════╗
║   ReconX — Web Enumeration              ║
║   Phase 2: Dirs + Tech + Admin Hunt     ║
║   github.com/jay-sharma-sec             ║
╚══════════════════════════════════════════╝

[*] Fingerprinting technology stack...
[+] Web Server:     Apache/2.4.25 (Debian)
[!] Apache 2.4.25 is outdated — check CVE database
[+] Language:       PHP (PHPSESSID cookie detected)
[+] CMS Detected:   DVWA
[!] Missing security headers: CSP, X-Frame-Options, X-Content-Type-Options, HSTS

[*] Starting directory brute force (116 paths)...

[FOUND ] 200 | http://localhost:8080/login.php           | Size: 1523B
[REDIR ] 302 | http://localhost:8080/phpinfo.php         | Size: 0B
[FORBID] 403 | http://localhost:8080/.htpasswd           | Size: 295B
[FORBID] 403 | http://localhost:8080/.htaccess           | Size: 295B
[FOUND ] 200 | http://localhost:8080/robots.txt          | Size: 26B
[FOUND ] 200 | http://localhost:8080/CHANGELOG.md        | Size: 7296B

[*] Directory scan complete in 0s — 6 path(s) found
```

## What Each Finding Means

**`login.php` — 200 OK**
Login page is exposed. Direct target for Phase 3 password attacks.

**`phpinfo.php` — 302 Redirect**
PHP info page redirected behind login. On misconfigured real servers this is often left open — reveals full server config, file paths, and sometimes credentials.

**`.htpasswd` / `.htaccess` — 403 Forbidden**
Files exist but access is blocked. A misconfigured server might expose these directly — `.htpasswd` contains hashed passwords.

**`robots.txt` — 200 OK**
Intended to hide pages from search engines. Often reveals sensitive paths developers forgot to actually secure.

**`CHANGELOG.md` — 200 OK**
Reveals exact software version and patch history — attackers use this to identify which vulnerabilities are still present.

## Legal Disclaimer

This tool is intended for **educational purposes and authorized penetration testing only**. Only use against targets you own or have explicit written permission to test. Unauthorized scanning is illegal.

## Author

**Jay Sharma** — [github.com/jay-sharma-sec](https://github.com/jay-sharma-sec) | [LinkedIn](https://www.linkedin.com/in/jay-sharma-cybersecurity-analyst)

---

*Part of the [ReconX](https://github.com/jay-sharma-sec/reconx) penetration testing toolkit.*
