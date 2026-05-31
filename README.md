# 🔐 CodeAlpha — Secure Coding Review
### Cyber Security Internship — Task 3

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.x-black?style=flat&logo=flask)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-purple?style=flat&logo=linux)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat)

---

## 📌 Description

A complete secure code review performed on a vulnerable Python Flask web application.
The review identified 10 security vulnerabilities, documented findings,
and provided a fully fixed secure version with remediation for each issue.

---

## 🗂️ Project Structure
CodeAlpha_SecureCodingReview/
├── vulnerable_app.py          # App with 10 intentional vulnerabilities
├── secure_app.py              # Fixed secure version
├── security_review_report.md  # Full findings & remediation report
└── README.md

---

## 🔍 Vulnerabilities Found

| ID      | Vulnerability            | Severity | CWE     |
|---------|--------------------------|----------|---------|
| VULN-01 | SQL Injection            | Critical | CWE-89  |
| VULN-02 | Command Injection        | Critical | CWE-78  |
| VULN-03 | Insecure Deserialization | Critical | CWE-502 |
| VULN-04 | Hardcoded Credentials    | Critical | CWE-798 |
| VULN-05 | Weak Cryptography (MD5)  | High     | CWE-327 |
| VULN-06 | Broken Access Control    | High     | CWE-284 |
| VULN-07 | Path Traversal           | High     | CWE-22  |
| VULN-08 | Insecure File Upload     | High     | CWE-434 |
| VULN-09 | Sensitive Data Exposure  | Medium   | CWE-200 |
| VULN-10 | Information Disclosure   | Medium   | CWE-209 |

---

## 🧪 Proof of Concept

### SQL Injection
```bash
curl -X POST http://127.0.0.1:5000/login \
  -d "username=admin' --&password=anything"
# Result: {"message": "Welcome admin' --", "status": "success"}
```

### Command Injection
```bash
curl "http://127.0.0.1:5000/ping?host=127.0.0.1;id"
# Result: uid=0(root) gid=0(root) groups=0(root)
```

### Broken Access Control
```bash
curl http://127.0.0.1:5000/admin
# Result: All users and passwords exposed
```

---

## 🛠️ Requirements

```bash
sudo apt install python3-flask python3-bcrypt -y
```

---

## 🚀 Usage

```bash
# Run vulnerable app
sudo python3 vulnerable_app.py

# Run secure app
sudo python3 secure_app.py
```

---

## ✅ Fixes Applied

| Vulnerability | Fix |
|---|---|
| SQL Injection | Parameterized queries |
| Command Injection | Input validation + no shell=True |
| Insecure Deserialization | JSON instead of pickle |
| Hardcoded Credentials | Environment variables |
| Weak Cryptography | bcrypt instead of MD5 |
| Broken Access Control | login_required + admin_required decorators |
| Path Traversal | Safe directory enforcement |
| Insecure File Upload | Extension whitelist + size limit |
| Sensitive Data Exposure | Removed debug endpoint |
| Information Disclosure | Generic error messages + logging |

---

## ⚠️ Disclaimer

This project is for **educational purposes only**.
The vulnerable app must never be deployed in a real environment.

---

## 👤 Author

**Fathy wael** — CodeAlpha Cyber Security Intern
GitHub: [@fathy889](https://github.com/fathy889)

---

*CodeAlpha Cyber Security Internship — Task 3*
