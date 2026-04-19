# ReconX — Phase 3: Password Attacks

A Python-based password attack module that performs intelligent login form analysis, default credential testing, and threaded wordlist brute forcing. Phase 3 of the ReconX penetration testing toolkit.

## What It Does

| Feature | Description |
|---|---|
| Login Form Analyser | Automatically detects field names, CSRF tokens, and form structure |
| Failure Fingerprinting | Learns what a failed login looks like to accurately detect success |
| Default Credentials | Tests 50+ real-world default credential pairs used by common platforms |
| Wordlist Brute Force | Threaded password attacks using built-in or custom wordlists |
| Auto-Stop | Immediately halts all threads the moment valid credentials are found |
| Report Generation | Saves all findings to a timestamped `.txt` report |

## How It Works

### Login Form Analysis
Before attacking, the scanner intelligently reads the login page HTML to find:
- Username and password field names (varies per site: `username`, `email`, `user`, `login`)
- CSRF tokens — security tokens that change every page load and must be submitted with each request
- Form action URL — where credentials are actually submitted
- Submit button name/value — some forms require this to process the request

### Failure Fingerprinting
Submits a deliberately wrong login first and records the response:
```
Failed login: HTTP 200 | Size: 1523B | Keyword: 'invalid'
```
This becomes the baseline. Any response that significantly differs — different URL, different size, missing error keyword — is flagged as a potential successful login.

### Detection Logic
A login attempt is considered successful when ALL of these are true:
- Response URL changed (redirected away from login page)
- Failure keyword absent from response body
- OR explicit success indicators present (`dashboard`, `welcome`, `logout`)

### CSRF Token Handling
If a CSRF token is detected, the scanner fetches a fresh token before **every single attempt** — because each page load generates a new token and submitting an old one will be rejected by the server.

### Threading with Auto-Stop
```
5 threads running simultaneously
Each thread grabs a password from the shared queue
First thread to find valid credentials sets a stop flag
All other threads see the flag and halt immediately
```

## Requirements

```bash
pip3 install requests beautifulsoup4
# or
sudo apt install python3-requests python3-bs4
```

## Usage

```bash
python3 reconx_day3.py -u <login_url> -U <username>
```

### Examples

```bash
# Default credentials check + built-in wordlist brute force
python3 reconx_day3.py -u http://localhost:8080/login.php -U admin

# Use a custom wordlist (e.g. rockyou.txt)
python3 reconx_day3.py -u http://localhost:8080/login.php -U admin -w /usr/share/wordlists/rockyou.txt

# Only check default credentials, skip brute force
python3 reconx_day3.py -u http://localhost:8080/login.php -U admin --skip-brute

# Slower, stealthier scan — bigger delay, fewer threads
python3 reconx_day3.py -u http://localhost:8080/login.php -U admin --threads 2 --delay 1.0
```

### Sample Output

```
╔══════════════════════════════════════════╗
║   ReconX — Password Attacks             ║
║   Phase 3: Default Creds + BruteForce  ║
║   github.com/jay-sharma-sec             ║
╚══════════════════════════════════════════╝

[*] Analysing login form at http://localhost:8080/login.php...
[+] Username field: 'username'
[+] Password field: 'password'
[~] Hidden field found: user_token = a3f92b1c...
[!] CSRF token detected — will refresh per request
[+] Form submits to: http://localhost:8080/login.php

[*] Fingerprinting failed login response...
[+] Failed login: HTTP 200 | Size: 1523B | Keyword: 'invalid'

[*] Testing 50 default credential pairs...
[~] Tested 10/50 pairs...
[~] Tested 20/50 pairs...

[!!!] DEFAULT CREDENTIALS FOUND!
      Username: admin
      Password: password
      Redirected to: http://localhost:8080/index.php

──────────────────────────────────────────────────
[!!!] 1 valid credential(s) found — check report
──────────────────────────────────────────────────
```

## Default Credentials Covered

The scanner tests credentials for:

| Platform | Example Defaults |
|---|---|
| Generic web apps | admin/admin, admin/password, root/root |
| DVWA | admin/password, gordonb/abc123, pablo/letmein |
| WordPress | admin/admin, wordpress/wordpress |
| Routers/Devices | admin/1234, cusadmin/highspeed |
| Common weak passwords | admin/qwerty, admin/letmein, admin/123456 |

## Real World Context

Password attacks are one of the most common attack vectors in real penetration tests because:

- **Default credentials** are never changed on a surprising number of production systems
- **Password reuse** means credentials leaked in one breach work on other platforms
- **Weak passwords** remain extremely common despite years of security awareness training
- **No rate limiting** on many internal applications means brute force is fast and effective

## Using rockyou.txt (Recommended for Real Testing)

```bash
# Install wordlists on Kali Linux
sudo apt install wordlists
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Use with ReconX
python3 reconx_day3.py -u http://target/login -U admin -w /usr/share/wordlists/rockyou.txt --threads 3 --delay 0.5
```

## Legal Disclaimer

This tool is intended for **educational purposes and authorized penetration testing only**. Only use against systems you own or have explicit written permission to test. Unauthorized access is illegal under the IT Act 2000 (India) and equivalent laws worldwide.

## Author

**Jay Sharma** — [github.com/jay-sharma-sec](https://github.com/jay-sharma-sec) | [LinkedIn](https://www.linkedin.com/in/jay-sharma-cybersecurity-analyst)

---

*Part of the [ReconX](https://github.com/jay-sharma-sec/reconx) penetration testing toolkit.*
