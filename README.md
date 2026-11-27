# FileWatch – File Integrity Monitoring System

**A Python-Based Cybersecurity Project**

## 1. Project Overview

FileWatch is a Python-based File Integrity Monitoring (FIM) system designed to detect unauthorized changes to files using the SHA-256 cryptographic hashing algorithm.

The system monitors a designated folder, compares file hashes against an original baseline, detects suspicious file activities, and records security events with timestamps and hash evidence.

It also provides real-time security alerts and a web-based dashboard for monitoring file integrity.

## 2. Key Features

- **SHA-256 Hashing:** Generates cryptographic hashes to verify file integrity.
- **Baseline Creation:** Stores original file hashes for future comparisons.
- **Real-Time Monitoring:** Detects file creation, modification, deletion, and movement.
- **Security Alerts:** Displays alerts when suspicious file activities are detected.
- **Advanced Security Logging:** Records timestamps, event types, filenames, and old/new SHA-256 hashes.
- **Professional Dashboard:** Displays file status, security events, severity levels, and deleted file history.
- **Event Classification:** Categorizes events as SAFE, NEW, MODIFIED, or DELETED.

## 3. Technologies Used

- Python
- SHA-256 (Hashlib)
- Watchdog
- Streamlit
- JSON
- Visual Studio Code

## 4. Project Structure

```text
FileWatch/
│
├── main.py
├── dashboard.py
├── baseline.json
├── security.log
│
├── test_folder/
│   ├── file1.txt
│   ├── file2.txt
│   └── ...
│
└── README.md
```

## 5. Installation

Clone the repository:

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd FileWatch
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the required libraries:

```bash
pip install watchdog streamlit
```

## 6. How to Run

### Start the File Integrity Monitor

```bash
python main.py
```

The system will scan the monitored folder, compare files against the baseline, and start real-time monitoring.

### Launch the Security Dashboard

Open a second terminal, activate the virtual environment, and run:

```bash
python -m streamlit run dashboard.py
```

## 7. Security Testing

The system can be tested by performing the following actions inside `test_folder`:

| Test | Expected Detection |
|---|---|
| Create a new file | NEW |
| Modify an existing file | MODIFIED |
| Delete a file | DELETED |
| Keep a file unchanged | SAFE |

Each detected security event is recorded in `security.log` with relevant SHA-256 evidence.

## 8. Ethical Considerations

FileWatch is designed for educational and defensive cybersecurity purposes.

It should only be used to monitor files and directories that the user owns or has explicit authorization to monitor.

## 9. Project Objective

The main objective of FileWatch is to demonstrate how cryptographic hashing, file system monitoring, security event logging, and dashboard visualization can work together to improve file integrity monitoring and detect unauthorized file changes.

---

**Project:** FileWatch – File Integrity Monitoring System  
**Category:** Cybersecurity  
**Language:** Python