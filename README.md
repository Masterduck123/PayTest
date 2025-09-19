# PayTest

**PayTest** is a command-line tool for sending HTTP requests securely and anonymously through the Tor network. All responses are encrypted and logged locally for review.

---

## Features

- Send HTTP payloads (`GET`, `POST`, `PUT`, etc.) via Tor.
- Supports custom headers, form data, and JSON.
- All responses are AES-encrypted using `Fernet`.
- Automatically checks and manages Tor process.
- Optionally supports custom proxies (`--proxy`).
- Encrypted logs can be viewed later.

---

## Requirements

- Python 3.8+
- Python libraries:
  - `requests`
  - `cryptography`
  - `argparse`
- Tor installed and available in your PATH (`tor`)

---

## Installation

```bash
git clone https://github.com/youruser/paytest.git
cd paytest
pip install -r requirements.txt
