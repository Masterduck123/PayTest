import os
import re
import sys
import time
import json
import requests
import subprocess
import argparse
import platform
from getpass import getpass
from threading import Thread
from typing import Optional, Dict, Any, List
from cryptography.fernet import Fernet, InvalidToken

# === CONSTANTS ===
KEY_FILE = "encryption_key.key"
LOG_FILE = "logs.enc"
TOR_PROXY = "socks5h://127.0.0.1:9050"
TOR_CHECK_URL = "https://check.torproject.org/api/ip"
SUPPORTED_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

HELP_TEXT = """
Paytest - HTTP Payload Tester via Tor

Available commands:
  -h, --help         Show this help menu
  -exit              Exit the program
  -clear             Clear the terminal
  send               Send a payload to the given URL using HTTP method
  showlogs           Decrypt and show payload logs
  starttor           Start/restart the Tor process
  stoptor            Stop the Tor process (if started here)
  keyreset           Regenerate the encryption key (logs will be unreadable)
  config             Show/change basic configuration

--------------------------------------------------------------
Supported HTTP Methods for sending payloads:
  GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS

Send command usage:
  send URL -m METHOD [-p PAYLOAD] [-ph HEADER:VAL ...] [-pb KEY=VAL ...] [--json] [--proxy PROXY_URL]

Options:
  URL            Target to send the request to. Should include scheme (http/https).
  -m METHOD      HTTP method to use (see above).
  -p PAYLOAD     Payload string. Can be a value, JSON, or parameter string.
  -ph HEADER:VAL Header(s) to send, e.g. -ph "User-Agent:Test" (can be repeated).
  -pb KEY=VAL    Body parameters (for form data); e.g. -pb username=duck (can be repeated).
  --json         Send payload/body as JSON (Content-Type: application/json).
  --proxy URL    Use a specific proxy instead of Tor (e.g. --proxy http://127.0.0.1:8080).

Examples:
  send https://target.com -m POST -p 'user=foo' -ph "User-Agent:Test"
  send https://target.com/api -m GET -ph "Authorization:Bearer token" --json
  send http://site.local -m PUT -pb key1=val1 -pb key2=val2 --json
  send https://example.com -m DELETE --proxy socks5h://127.0.0.1:9050

Notes:
- All requests use Tor as proxy by default (unless --proxy is specified).
- All responses are encrypted and saved to logs.enc.
- Use 'showlogs' to decrypt and view previous responses (requires encryption key).
- Regenerating the key will make old logs unreadable.
- For security, never share your encryption key.

For more information, read the documentation or contact the author.
"""

# === ENCRYPTION SYSTEM ===
def generate_encryption_key() -> bytes:
    return Fernet.generate_key()

def save_encryption_key(key: bytes) -> None:
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

def load_encryption_key(interactive: bool = True) -> bytes:
    try:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
            Fernet(key)  # Validate key
            return key
    except (FileNotFoundError, InvalidToken):
        print("[!] Invalid or missing encryption key.")
        if not interactive:
            sys.exit(1)
        resp = input("[!] Regenerate key? This will make old logs unreadable! (yes/no): ").strip().lower()
        if resp == "yes":
            key = generate_encryption_key()
            save_encryption_key(key)
            return key
        else:
            print("[!] Exiting program to avoid data loss.")
            sys.exit(1)

def encrypt_string(data: str, key: bytes) -> bytes:
    return Fernet(key).encrypt(data.encode())

def decrypt_string(data: bytes, key: bytes) -> Optional[str]:
    try:
        return Fernet(key).decrypt(data).decode()
    except InvalidToken:
        return None

def ensure_key_exists() -> bytes:
    if not os.path.exists(KEY_FILE):
        key = generate_encryption_key()
        save_encryption_key(key)
        return key
    return load_encryption_key()

key = ensure_key_exists()

# === TOR CONTROL ===
def is_command_installed(cmd: str) -> bool:
    return subprocess.call(["which", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def check_tor_process() -> bool:
    result = subprocess.run(["pgrep", "-x", "tor"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0

def validate_tor_connection(proxy: str = TOR_PROXY) -> bool:
    try:
        session = requests.Session()
        session.proxies = {'http': proxy, 'https': proxy}
        response = session.get(TOR_CHECK_URL, timeout=10)
        return response.status_code == 200 and response.json().get("IsTor", False)
    except requests.exceptions.RequestException:
        return False

def stream_tor_output(process, flag):
    for line in iter(process.stdout.readline, ''):
        decoded_line = line.strip()
        print(decoded_line)
        if "Bootstrapped 100%" in decoded_line:
            flag[0] = True
            break

def start_tor_process() -> Optional[subprocess.Popen]:
    if not is_command_installed("tor"):
        print("[!] Tor is not installed. Please install Tor.")
        return None

    if check_tor_process() and validate_tor_connection():
        print("[+] Tor is already running and healthy.")
        return None
    elif check_tor_process():
        print("[!] Tor is running but not healthy. Restarting...")
        stop_tor_process(None)

    try:
        process = subprocess.Popen(["tor"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        flag = [False]
        monitor_thread = Thread(target=stream_tor_output, args=(process, flag))
        monitor_thread.start()

        for _ in range(30):
            if flag[0]:
                print("[+] Tor started successfully.")
                return process
            time.sleep(1)

        print("[!] Tor bootstrap failed.")
        return None
    except Exception as e:
        print(f"[!] Error starting Tor: {e}")
        return None

def stop_tor_process(process):
    if process and process.poll() is None:
        try:
            process.terminate()
            process.wait()
            print("[+] Tor process terminated.")
        except Exception as e:
            print(f"[!] Error stopping Tor process: {e}")
    else:
        # Try to kill any running Tor process (if not started here)
        subprocess.run(["pkill", "-x", "tor"])

# === PAYLOAD TESTING ===
def is_valid_url(url: str) -> bool:
    regex = re.compile(
        r'^(https?|ftp):\/\/[\w\-\.]+(:\d+)?(\/\S*)?$', re.IGNORECASE)
    return re.match(regex, url) is not None

def parse_headers(header_list: List[str]) -> Dict[str, str]:
    headers = {}
    if header_list:
        for h in header_list:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
    return headers

def parse_body(body_list: List[str]) -> Dict[str, str]:
    body = {}
    if body_list:
        for b in body_list:
            if "=" in b:
                k, v = b.split("=", 1)
                body[k.strip()] = v.strip()
    return body

def send_payload(args: argparse.Namespace, key: bytes):
    if not is_valid_url(args.url):
        print("[!] Invalid URL")
        return

    session = requests.Session()
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}
    else:
        session.proxies = {"http": TOR_PROXY, "https": TOR_PROXY}

    headers = parse_headers(args.ph or [])
    data = parse_body(args.pb or [])
    payload = args.p
    json_data = None

    if args.json:
        if data:
            json_data = data
        elif payload:
            try:
                json_data = json.loads(payload)
            except Exception:
                json_data = {"payload": payload}
    else:
        if payload:
            data["payload"] = payload

    try:
        method = args.m.upper()
        if method not in SUPPORTED_METHODS:
            print(f"[!] Method {method} not supported.")
            return

        req_args = {
            "url": args.url,
            "headers": headers,
            "timeout": 20
        }

        if method == "GET":
            req_args["params"] = data
        elif method == "POST":
            if json_data:
                req_args["json"] = json_data
            else:
                req_args["data"] = data
        elif method in ["PUT", "PATCH", "DELETE"]:
            if json_data:
                req_args["json"] = json_data
            else:
                req_args["data"] = data

        response = session.request(method, **req_args)

        print(f"[+] Sent to: {response.url}")
        print(f"[+] Status code: {response.status_code}")
        print("[+] Response body:")
        print(response.text[:10000])  # Avoid overflow

        waf_keywords = ["access denied", "blocked", "forbidden", "firewall", "waf"]
        if any(word in response.text.lower() for word in waf_keywords):
            print("[!] Possible WAF detected.")

        encrypted = encrypt_string(f"URL: {args.url}\nMethod: {method}\nHeaders: {headers}\nBody: {data}\nResponse: {response.text}", key)
        with open(LOG_FILE, "ab") as log:
            log.write(encrypted + b"\n")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error sending payload: {e}")

# === LOG MANAGEMENT ===
def show_logs(key: bytes):
    if not os.path.exists(LOG_FILE):
        print("[!] No logs found.")
        return
    print("[*] Decrypting logs...")
    with open(LOG_FILE, "rb") as log:
        for i, line in enumerate(log, 1):
            try:
                dec = decrypt_string(line.strip(), key)
                if dec:
                    print(f"\n--- Log [{i}] ---\n{dec}\n{'-'*40}")
                else:
                    print(f"[!] Log [{i}]: Unable to decrypt. Wrong key?")
            except Exception as e:
                print(f"[!] Log [{i}]: Error: {e}")

def reset_key():
    print("[!] WARNING: This will make all existing logs unreadable!")
    confirm = input("Type YES to continue: ")
    if confirm.strip().upper() == "YES":
        key = generate_encryption_key()
        save_encryption_key(key)
        print("[+] Key regenerated.")
        try:
            os.rename(LOG_FILE, LOG_FILE + ".old")
            print(f"[+] Old logs moved to {LOG_FILE}.old")
        except Exception:
            pass
        return key
    else:
        print("[!] Key reset cancelled.")
        return None

# === UTILITY FUNCTIONS ===
def clear_terminal():
    if platform.system() == "Windows":
        subprocess.run(["cls"], shell=True)
    else:
        subprocess.run(["clear"])

def show_help_menu():
    print(HELP_TEXT)

def show_config():
    print(f"Encryption key file: {KEY_FILE}")
    print(f"Logs file: {LOG_FILE}")
    print(f"Default proxy: {TOR_PROXY}")
    print(f"Tor check URL: {TOR_CHECK_URL}")

# === MAIN FUNCTION / CLI LOOP ===
def main():
    global key
    tor_process = None
    print(r"""
  ___  ___   _______ ___ ___ _____ 
 | _ \/_\ \ / /_   _| __/ __|_   _|
 |  _/ _ \ V /  | | | _|\__ \ | |  
 |_|/_/ \_\_|   |_| |___|___/ |_|  
                                   
    Type -h for help""")
    while True:
        try:
            user_input = input(">>> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[+] Exiting. Goodbye!")
            break

        if user_input in ["-exit", "exit", "quit", "q"]:
            print("[+] Exiting. Goodbye!")
            if tor_process:
                stop_tor_process(tor_process)
            break
        elif user_input in ["-h", "--help", "help"]:
            show_help_menu()
        elif user_input in ["-clear", "clear"]:
            clear_terminal()
        elif user_input.startswith("send "):
            parser = argparse.ArgumentParser(prog="send", add_help=False)
            parser.add_argument("url", type=str)
            parser.add_argument("-m", type=str, required=True, help="HTTP method")
            parser.add_argument("-p", type=str, help="Payload or body (string)")
            parser.add_argument("-ph", action="append", help="Header (Header:Value)")
            parser.add_argument("-pb", action="append", help="Body param (k=v)")
            parser.add_argument("--json", action="store_true", help="Send as JSON")
            parser.add_argument("--proxy", type=str, help="Proxy URL (default: Tor)")
            try:
                args = parser.parse_args(user_input.split()[1:])
                send_payload(args, key)
            except SystemExit:
                print("[!] Invalid arguments. Example: send https://site -m POST -p foo -ph 'User-Agent:bar'")
        elif user_input == "showlogs":
            show_logs(key)
        elif user_input == "starttor":
            tor_process = start_tor_process()
        elif user_input == "stoptor":
            stop_tor_process(tor_process)
            tor_process = None
        elif user_input == "keyreset":
            k = reset_key()
            if k:
                key = k
        elif user_input == "config":
            show_config()
        else:
            print("[!] Unknown command. Use -h for help.")

if __name__ == "__main__":
    main()