#!/usr/bin/env python3
"""
==========================================================
  SECURE PYTHON WEB APPLICATION
  CodeAlpha — Task 3: Secure Coding Review
  Fixed version after security audit
==========================================================
"""

from flask import Flask, request, jsonify, session
from functools import wraps
from werkzeug.utils import secure_filename
import sqlite3
import subprocess
import bcrypt
import logging
import os
import json
import re
import base64

app = Flask(__name__)

# FIX 1: Secrets from environment variables
app.secret_key     = os.environ.get("SECRET_KEY", os.urandom(32))
UPLOAD_FOLDER      = os.environ.get("UPLOAD_FOLDER", "/tmp/uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf"}
MAX_FILE_SIZE      = 5 * 1024 * 1024

logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE,
                    password TEXT,
                    email TEXT,
                    role TEXT DEFAULT 'user'
                )""")
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return decorated

# FIX 2: SQL Injection — Parameterized Queries
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    if user and bcrypt.checkpw(password.encode(), user[2].encode()):
        session["user"] = username
        session["role"] = user[4]
        return jsonify({"status": "success", "message": f"Welcome {username}"})
    logging.warning(f"Failed login attempt for username: {username}")
    return jsonify({"status": "fail", "message": "Invalid credentials"}), 401

# FIX 3: Command Injection — Validation + No shell=True
@app.route("/ping", methods=["GET"])
@login_required
def ping():
    host = request.args.get("host", "")
    if not re.match(r'^[a-zA-Z0-9\.\-]{1,253}$', host):
        return jsonify({"error": "Invalid host format"}), 400
    result = subprocess.check_output(["ping", "-c", "1", host], timeout=5)
    return result

# FIX 4: Insecure File Upload — Validation + Sanitization
def allowed_file(filename):
    return "." in filename and \
           filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    file = request.files.get("file")
    if not file or not file.filename:
        return jsonify({"error": "No file provided"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400
    file.seek(0, 2)
    if file.tell() > MAX_FILE_SIZE:
        return jsonify({"error": "File too large"}), 413
    file.seek(0)
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    return jsonify({"status": "uploaded", "filename": filename})

# FIX 5: bcrypt instead of MD5
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    email    = request.form.get("email", "").strip()
    if not username or not password or not email:
        return jsonify({"error": "All fields required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password, email) VALUES (?,?,?)",
                  (username, hashed, email))
        conn.commit()
        conn.close()
        return jsonify({"status": "registered"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

# FIX 6: JSON instead of pickle
@app.route("/profile", methods=["GET"])
@login_required
def profile():
    data = request.args.get("data", "")
    try:
        decoded = base64.b64decode(data).decode()
        obj     = json.loads(decoded)
        return jsonify({"profile": obj})
    except Exception:
        return jsonify({"error": "Invalid data format"}), 400

# FIX 7: Broken Access Control — Auth required
@app.route("/admin", methods=["GET"])
@login_required
@admin_required
def admin():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT id, username, email, role FROM users")
    users = c.fetchall()
    conn.close()
    return jsonify({"users": users})

# FIX 8: Path Traversal — Safe directory enforcement
SAFE_DIRECTORY = os.path.realpath("/var/app/files")

@app.route("/read", methods=["GET"])
@login_required
def read_file():
    filename = request.args.get("file", "")
    safe_path = os.path.realpath(os.path.join(SAFE_DIRECTORY, filename))
    if not safe_path.startswith(SAFE_DIRECTORY):
        logging.warning(f"Path traversal attempt: {filename}")
        return jsonify({"error": "Access denied"}), 403
    if not os.path.isfile(safe_path):
        return jsonify({"error": "File not found"}), 404
    with open(safe_path, "r") as f:
        return f.read()

# FIX 9: Generic error messages
@app.route("/user/<int:user_id>", methods=["GET"])
@login_required
def get_user(user_id):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    try:
        c.execute("SELECT id, username, email FROM users WHERE id=?", (user_id,))
        user = c.fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404
        return jsonify({"user": user})
    except Exception as e:
        logging.error(f"Error fetching user {user_id}: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=False, host="127.0.0.1", port=5000)

