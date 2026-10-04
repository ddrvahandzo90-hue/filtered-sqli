"""
CTF Challenge: "Filtered Login" - Web Exploitation (Low)

Vuln: SQL Injection in login form, protected by a NAIVE blacklist filter
that blocks the literal word "or" (case-insensitive) with surrounding
spaces. Players must bypass the filter (e.g. using SQL inline comments
/**/ instead of spaces) to still perform the classic auth-bypass payload.

Intentionally vulnerable. Do NOT use this pattern in real applications.
"""

from flask import Flask, request, render_template, g, session, redirect, url_for, Response
import sqlite3
import os
import binascii
import secrets

APP_DB = os.path.join(os.path.dirname(__file__), "ctf2.db")
FLAG = os.environ.get("FLAG", "MGSTC{f1lt3r_byp4ss_c0mm3nt_tr1ck}")
FLAG_HEX = binascii.hexlify(FLAG.encode()).decode()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))

# Naive blacklist: blocks " or " (with spaces) case-insensitively.
# Intended bypass: use /**/ or other whitespace tricks instead of spaces,
# e.g.  admin'/**/OR/**/'1'='1
BLOCKED_PATTERNS = [" or ", "\tor\t", "\nor\n"]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(APP_DB)
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(APP_DB)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
        """
    )
    cur.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        ("admin", "N0t_Gu3ss4bl3_Pw_z7Lk", "admin"),
    )
    cur.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        ("member", "member123", "user"),
    )
    conn.commit()
    conn.close()


def contains_blocked_pattern(text: str) -> bool:
    lowered = text.lower()
    return any(pat in lowered for pat in BLOCKED_PATTERNS)


@app.route("/", methods=["GET"])
def index():
    return render_template("login.html", error=None)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # --- "WAF"-like filter: naively blocks " or " with spaces ---
    if contains_blocked_pattern(username) or contains_blocked_pattern(password):
        return render_template(
            "login.html",
            error="🚫 Blocked by security filter: the word 'OR' (with spaces) is not allowed.",
        )

    db = get_db()
    cur = db.cursor()

    # --- VULNERABLE QUERY: direct string concatenation, no parameterization ---
    query = "SELECT id, username, role FROM users WHERE username = '" + username + \
            "' AND password = '" + password + "'"
    try:
        cur.execute(query)
        row = cur.fetchone()
    except sqlite3.Error as e:
        return render_template("login.html", error=f"Database error: {e}")

    if row:
        user_id, uname, role = row
        session["username"] = uname
        session["role"] = role
        return render_template("success.html", role=role, username=uname)

    return render_template("login.html", error="Invalid username or password.")


@app.route("/robots.txt")
def robots():
    content = (
        "User-agent: *\n"
        "Disallow: /admin-settings\n"
    )
    return Response(content, mimetype="text/plain")


@app.route("/admin-settings")
def admin_settings():
    if session.get("role") != "admin":
        return render_template("login.html", error="403 Forbidden: admin only."), 403
    return render_template("admin_settings.html", username=session.get("username"), flag_hex=FLAG_HEX)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
