"""Deliberately vulnerable demo app used to test gsa. NEVER deploy this."""
import sqlite3
from pathlib import Path

from flask import Flask, jsonify, make_response, request

app = Flask(__name__)
DB = Path(__file__).with_name("demo.sqlite3")


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init():
    conn = db()
    conn.executescript((Path(__file__).parent / "db" / "schema.sql").read_text())
    conn.execute("INSERT OR IGNORE INTO users (id, email, password, name) VALUES (1, 'admin@example.com', 'hunter2', 'Admin')")
    conn.commit()


@app.route("/api/login", methods=["POST"])
def login():
    email = request.json.get("email")
    password = request.json.get("password")
    # SQL injection on purpose
    row = db().execute(f"SELECT * FROM users WHERE email = '{email}' AND password = '{password}'").fetchone()
    if not row:
        return jsonify({"error": "invalid"}), 401
    resp = make_response(jsonify({"ok": True}))
    resp.set_cookie("session", "demo-session-abcdef123456")
    return resp


@app.route("/login")
def login_page():
    resp = make_response(
        "<html><body><h1>Demo login</h1><script>"
        "localStorage.setItem('access_token','eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlZGVtbw');"
        "</script></body></html>"
    )
    resp.set_cookie("session", "demo-session-abcdef123456", httponly=True)
    return resp


@app.route("/api/me", methods=["GET"])
def me():
    if request.cookies.get("session") != "demo-session-abcdef123456":
        return jsonify({"error": "auth required"}), 401
    return jsonify({"id": 1, "email": "admin@example.com", "name": "Admin", "org_id": 3})


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<html><body>Results for {q}</body></html>"


@app.route("/api/posts", methods=["GET", "POST"])
def posts():
    if request.method == "POST":
        title = request.json.get("title")
        body = request.json.get("body")
        conn = db()
        conn.execute("INSERT INTO posts (title, body, user_id) VALUES (?, ?, 1)", (title, body))
        conn.commit()
        return jsonify({"ok": True}), 201
    rows = db().execute("SELECT * FROM posts LIMIT 5").fetchall()
    return jsonify({"data": [dict(r) for r in rows]})


if __name__ == "__main__":
    init()
    app.run(port=5055)
