# CodeAlpha — Secure Coding Review Report
## Task 3 | Cyber Security Internship

**Application:** vulnerable_app.py (Python Flask Web Application)
**Reviewer:** [Your Name]
**Date:** 2025
**Language:** Python 3.x + Flask

---

## Executive Summary

A manual secure code review was performed on a Python Flask web application.
The review identified 10 security vulnerabilities across multiple attack categories.

| Severity | Count |
|----------|-------|
| Critical | 4     |
| High     | 4     |
| Medium   | 2     |
| Total    | 10    |

---

## Vulnerability Findings

### [VULN-01] SQL Injection
**Severity:** Critical | **CWE:** CWE-89

Vulnerable Code:
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

Description:
User input directly concatenated into SQL queries.
Attacker bypasses login with: username = admin' --
Proof: {"message": "Welcome admin' --", "status": "success"}

Fix:
c.execute("SELECT * FROM users WHERE username=?", (username,))

---

### [VULN-02] Command Injection
**Severity:** Critical | **CWE:** CWE-78

Vulnerable Code:
result = subprocess.check_output(f"ping -c 1 {host}", shell=True)

Description:
User input passed directly to shell.
Attacker runs: GET /ping?host=127.0.0.1;id
Proof: uid=0(root) gid=0(root) groups=0(root)

Fix:
result = subprocess.check_output(["ping", "-c", "1", host])

---

### [VULN-03] Insecure Deserialization
**Severity:** Critical | **CWE:** CWE-502

Vulnerable Code:
obj = pickle.loads(decoded)

Description:
pickle.loads() on untrusted data allows Remote Code Execution.

Fix:
obj = json.loads(base64.b64decode(data))

---

### [VULN-04] Hardcoded Credentials
**Severity:** Critical | **CWE:** CWE-798

Vulnerable Code:
app.secret_key = "supersecretkey123"
API_KEY = "sk-1234567890abcdef"

Fix:
app.secret_key = os.environ.get("SECRET_KEY")
API_KEY = os.environ.get("API_KEY")

---

### [VULN-05] Weak Cryptography
**Severity:** High | **CWE:** CWE-327

Vulnerable Code:
hashed = hashlib.md5(password.encode()).hexdigest()

Fix:
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

---

### [VULN-06] Broken Access Control
**Severity:** High | **CWE:** CWE-284

Vulnerable Code:
@app.route("/admin")
def admin():  # No auth check

Proof: {"all_users": [["admin","password"],["alice","1234"]]}

Fix:
@login_required
@admin_required
def admin():

---

### [VULN-07] Path Traversal
**Severity:** High | **CWE:** CWE-22

Vulnerable Code:
with open(filename, "r") as f:

Fix:
safe_path = os.path.realpath(os.path.join(SAFE_DIRECTORY, filename))
if not safe_path.startswith(SAFE_DIRECTORY):
    return jsonify({"error": "Access denied"}), 403

---

### [VULN-08] Insecure File Upload
**Severity:** High | **CWE:** CWE-434

Vulnerable Code:
filename = file.filename  # No sanitization

Fix:
filename = secure_filename(file.filename)
if not allowed_file(filename):
    return jsonify({"error": "Invalid file type"}), 400

---

### [VULN-09] Sensitive Data Exposure
**Severity:** Medium | **CWE:** CWE-200

Vulnerable Code:
return jsonify({"secret_key": app.secret_key, "environment": dict(os.environ)})

Proof: Returns all secrets + environment variables to any user.

Fix:
Remove debug endpoints entirely in production.

---

### [VULN-10] Information Disclosure
**Severity:** Medium | **CWE:** CWE-209

Vulnerable Code:
return jsonify({"error": str(e)}), 500

Fix:
logging.error(f"Error: {e}")
return jsonify({"error": "Internal server error"}), 500

---

## Summary Table

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

## Secure Coding Best Practices

1. Never trust user input
2. Use parameterized queries
3. Use bcrypt for passwords
4. Store secrets in environment variables
5. Implement proper access control
6. Sanitize file uploads
7. Disable debug mode in production
8. Use JSON instead of pickle

---

*CodeAlpha Cyber Security Internship — Task 3*

