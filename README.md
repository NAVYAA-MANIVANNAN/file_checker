# File Integrity Checker – SHA-256 Log Tampering Detection Tool

A professional, zero-dependency cybersecurity command-line tool built in Python to monitor files and directories for unauthorized changes, additions, or deletions. This tool calculates cryptographic **SHA-256 baseline hashes** and compares them against current states to detect integrity breaches in application logs, configuration files, and system files.

---

## 1. Project Overview

In cybersecurity, **File Integrity Monitoring (FIM)** is a critical defense control. Attackers often modify log files (e.g., in `/var/log` or application directories) to cover their tracks, hide malicious payloads, or escalate privileges.

By creating a trusted snapshot of system files—known as a **baseline**—and verifying it periodically, security administrators can detect changes immediately. This tool utilizes **SHA-256 hashing** (a secure, collision-resistant cryptographic hash function) to verify integrity. Comparing hashes is much more reliable than checking file sizes or modification times (timestamps), which can easily be falsified by advanced attackers using techniques like "timestomping".

---

## 2. Features

* **SHA-256 Cryptographic Integrity Check**: Reads files in 4096-byte chunks to maintain high performance and low memory footprints for large log files.
* **Directory & Single File Support**: Seamlessly monitors recursively down directory paths or works directly with a single specific file.
* **Baseline Database Storage**: Baseline data is securely stored outside the monitored directory at `~/.integrity_hashes.json` (resolves to the home folder on both Windows and Linux).
* **VCS & Temp Cache Ignoring**: Automatically skips `.git`, `.venv`, `__pycache__`, `.vscode`, `.DS_Store`, and temporary files (e.g., ending with `~`).
* **Complete Drift Detection**: Identifies:
  * `MODIFIED`: Existing baseline files whose current hash mismatches.
  * `NEW FILE`: Files added since the baseline was established.
  * `DELETED`: Monitored baseline files that are no longer present.
* **Interactive Baseline Updates**: Allows administrators to manually confirm and update baseline entries for legitimate updates (`update` command).
* **Resilient Execution**: Gracefully catches and displays `Permission denied` errors instead of crashing when encountering locked or unreadable files.

---

## 3. Installation & Requirements

### Requirements
* **Python 3.x**
* No external packages required (uses Python standard libraries only: `sys`, `os`, `hashlib`, `json`, `datetime`).

### Setup
Clone or place the project files into your desired workspace directory:
```text
file-integrity-checker/
│
├── integrity-check.py
├── README.md
├── requirements.txt
├── .gitignore
│
├── logs/
│   └── app.log
│
└── tests/
    └── test_integrity.py
```

Ensure the main script is executable (on Linux/macOS):
```bash
chmod +x integrity-check.py
```

---

## 4. Usage

Show the CLI help menu:
```bash
python3 integrity-check.py help
# or
python3 integrity-check.py --help
```

### Initialize Baseline
Establish the baseline hashes for a directory or file:
```bash
python3 integrity-check.py init ./logs
```

### Check File Integrity
Run checks against the baseline hashes at any time:
```bash
python3 integrity-check.py check ./logs
```

### Update Baseline
If you have verified that modifications are legitimate (e.g., expected log rotation or app update), update the trusted baseline database:
```bash
python3 integrity-check.py update ./logs
```
*Note: This command displays a diff of modifications, additions, and deletions, and prompts for confirmation (`y/N`) before writing changes.*

---

## 5. Demonstration Walkthrough

Follow these steps to demonstrate the tool:

### Step 1: Initialize Baseline
Run the `init` command on the sample log folder:
```bash
python3 integrity-check.py init ./logs
```
*Output:*
```text
[+] Initializing file integrity...
[+] SHA-256 hashes calculated.
[+] Hashes stored successfully.
```

### Step 2: Check Initial Status
Run `check` to verify that everything matches the baseline:
```bash
python3 integrity-check.py check ./logs
```
*Output:*
```text
[✓] logs/app.log
    Status: UNMODIFIED
    SHA-256: 41818d6a8a47ff7be5a0720... (full hash)
========================================
INTEGRITY CHECK SUMMARY
========================================
Unmodified : 1
Modified   : 0
New Files  : 0
Deleted    : 0
Errors     : 0

Overall Status: SECURE
========================================
```

### Step 3: Trigger Integrity Changes
Make modifications, deletions, and additions to simulate an incident:
1. **Modify** `logs/app.log` by appending a line (e.g. `[2026-08-15 12:15:00] INFO: Malicious action executed`).
2. **Add** a new file `logs/unauthorized_script.py`.
3. **Delete** a file if there were multiple (e.g., delete a log file).

### Step 4: Run Check and Detect Tampering
Run the check tool:
```bash
python3 integrity-check.py check ./logs
```
*Output:*
```text
[!] logs/app.log
    Status: MODIFIED
    Reason: SHA-256 hash mismatch
[+] logs/unauthorized_script.py
    Status: NEW FILE
    Reason: File was not present during initialization
========================================
INTEGRITY CHECK SUMMARY
========================================
Unmodified : 0
Modified   : 1
New Files  : 1
Deleted    : 0
Errors     : 0

Overall Status: WARNING
========================================
```

### Step 5: Update the Baseline
If the changes are legitimate, run:
```bash
python3 integrity-check.py update ./logs
```
*Output:*
```text
Pending Updates:
  [!] Modified: logs/app.log
  [+] New File: logs/unauthorized_script.py
Do you want to update the baseline database with these changes? (y/N): y
[+] Recalculating SHA-256 hash...
[+] Baseline hash updated successfully.
```

---

## 6. Security Concepts Learned

* **Cryptographic Hashing**: Using one-way mathematical functions to map arbitrary size data to a fixed-size signature (SHA-256 generates a unique 64-character hex string). Any minor file edit changes the hash entirely (the **avalanche effect**).
* **Log Tampering Detection**: Understanding how malicious actors erase or alter traces of their activities by editing logs, and how cryptographic verification exposes these attempts.
* **Baseline Comparison**: Separating trusted execution state from current runtime execution. Identifying drift across directories by tracking file lifecycle events (adds, modifications, deletions).
* **Incident Detection & Security Monitoring**: Setting up automated guardrails for security controls to continuously verify compliance and trigger alerts on drift (`Overall Status: WARNING`).
