# 🔐 File Integrity Checker – SHA-256 Log Tampering Detection Tool

A professional, zero-dependency cybersecurity command-line tool built with Python to detect unauthorized changes, additions, and deletions in files and directories.

The tool uses **SHA-256 cryptographic hashing** to create a trusted baseline and compare the current state of monitored files against that baseline.

---

## 🌐 Project URL

https://github.com/NAVYAA-MANIVANNAN/file_checker

---

## 📌 Project Overview

File Integrity Monitoring (FIM) is an important cybersecurity control used to detect unauthorized modifications to critical files.

Attackers may modify or delete application logs, configuration files, or system files to hide their activities. Simply checking file timestamps or file sizes is not sufficient because these values can potentially be manipulated.

This project creates a **SHA-256 hash baseline** for monitored files and compares the baseline against their current state.

Any change in file content results in a different SHA-256 hash, allowing the tool to identify potential integrity violations.

---

## 🚀 Features

* 🔐 SHA-256 cryptographic hashing
* 📁 Recursive directory monitoring
* 📄 Single-file integrity checking
* 🆕 New file detection
* ✏️ Modified file detection
* 🗑️ Deleted file detection
* 💾 JSON-based baseline storage
* 🔄 Interactive baseline updates
* ⚡ 4096-byte chunk-based file reading
* 🛡️ Permission error handling
* 🚫 Automatic temporary/cache file exclusion
* 🖥️ Windows and Linux compatible
* 📦 Zero external dependencies

---

## 🛠️ Technology Stack

| Technology | Purpose                       |
| ---------- | ----------------------------- |
| Python 3.x | Core development              |
| hashlib    | SHA-256 hashing               |
| os         | File and directory operations |
| json       | Baseline database storage     |
| datetime   | Timestamp handling            |
| sys        | CLI argument handling         |

---

## 📂 Project Structure

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

---

## ⚙️ Installation

### Requirements

* Python 3.x
* Git
* No external Python packages required

Clone the repository:

```bash
git clone https://github.com/NAVYAA-MANIVANNAN/file_checker.git
```

Move into the project directory:

```bash
cd file_checker
```

---

## ▶️ Usage

### Display Help

```bash
python integrity-check.py help
```

or:

```bash
python integrity-check.py --help
```

---

### 1. Initialize Baseline

Create a trusted SHA-256 baseline for a file or directory:

```bash
python integrity-check.py init ./logs
```

Example:

```text
[+] Initializing file integrity...
[+] SHA-256 hashes calculated.
[+] Hashes stored successfully.
```

The baseline is stored outside the monitored directory:

```text
~/.integrity_hashes.json
```

---

### 2. Check File Integrity

Run an integrity check against the stored baseline:

```bash
python integrity-check.py check ./logs
```

If no files have changed:

```text
[✓] logs/app.log
    Status: UNMODIFIED
    SHA-256: 41818d6a8a47ff7be5a0720...

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

---

### 3. Simulate File Tampering

Modify the sample log:

```text
logs/app.log
```

For example, append:

```text
[2026-08-15 12:15:00] INFO: Malicious action executed
```

You can also add a new file:

```text
logs/unauthorized_script.py
```

Then run:

```bash
python integrity-check.py check ./logs
```

---

## 🚨 Tampering Detection

Example output:

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

---

## 🔄 Update Baseline

When a detected change is legitimate, the administrator can update the trusted baseline:

```bash
python integrity-check.py update ./logs
```

The tool displays the detected changes and requests confirmation.

Example:

```text
Pending Updates:

  [!] Modified: logs/app.log
  [+] New File: logs/unauthorized_script.py

Do you want to update the baseline database with these changes? (y/N): y

[+] Recalculating SHA-256 hash...
[+] Baseline hash updated successfully.
```

---

## 🔍 Detection Types

The tool identifies four major file integrity states:

### ✏️ MODIFIED

A file existed in the original baseline but its SHA-256 hash has changed.

```text
Reason: SHA-256 hash mismatch
```

### 🆕 NEW FILE

A file exists in the monitored directory but was not present when the baseline was created.

```text
Reason: File was not present during initialization
```

### 🗑️ DELETED

A file existed in the baseline but is no longer available in the monitored directory.

### ✅ UNMODIFIED

The current SHA-256 hash matches the trusted baseline hash.

---

## 🚫 Ignored Files

The tool automatically ignores common development and temporary files/directories:

```text
.git
.venv
__pycache__
.vscode
.DS_Store
temporary files ending with ~
```

This prevents unnecessary integrity alerts from development artifacts and cache files.

---

## 🔐 Security Concepts Demonstrated

### 1. Cryptographic Hashing

SHA-256 converts file contents into a fixed-length 64-character hexadecimal hash.

Example:

```text
SHA-256:
41818d6a8a47ff7be5a0720...
```

Even a small change in a file produces a completely different hash.

---

### 2. File Integrity Monitoring

The project demonstrates how security teams can monitor critical files and identify unauthorized changes.

---

### 3. Log Tampering Detection

Attackers may attempt to modify or delete logs to hide malicious activity.

Hash-based integrity verification helps identify such changes.

---

### 4. Baseline Comparison

The project establishes a trusted state and compares future file states against it.

```text
Trusted Baseline
       ↓
Current File State
       ↓
SHA-256 Comparison
       ↓
Integrity Result
```

---

### 5. Incident Detection

Detected changes are classified as:

```text
MODIFIED
NEW FILE
DELETED
UNMODIFIED
```

The final result is reported as:

```text
SECURE
```

or:

```text
WARNING
```

---

## 🧪 Testing

The project includes a test directory:

```text
tests/
└── test_integrity.py
```

Testing should cover:

* File hashing
* Baseline creation
* Modified files
* New files
* Deleted files
* Permission errors
* Baseline updates

---

## 📦 Dependencies

This project intentionally uses only Python standard libraries.

No external packages are required.

```text
Python Standard Library
├── sys
├── os
├── hashlib
├── json
└── datetime
```

---

## 🎯 Use Cases

This tool can be used for:

* Application log monitoring
* Configuration file monitoring
* Security lab demonstrations
* Cybersecurity learning
* File tampering detection
* Basic incident detection
* Security operations training
* System integrity monitoring

---

## ⚠️ Security Note

This tool is intended for **educational, defensive, and authorized security monitoring purposes**.

For production environments, the baseline database itself should be protected using appropriate access controls and preferably stored in a trusted location that unauthorized users cannot modify.

---

## 👩‍💻 Author

**NAVYAA MANIVANNAN**

Cybersecurity & Java Full Stack Developer

---

## 🔗 Repository

https://github.com/NAVYAA-MANIVANNAN/file_checker

If you find this project useful, consider giving the repository a ⭐ star.

---

## 📜 License

This project is intended for educational and cybersecurity learning purposes.
