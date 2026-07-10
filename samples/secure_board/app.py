import os
import re
import sqlite3
import secrets
from functools import wraps
from pathlib import Path

from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE = Path(__file__).resolve().parent
DB = BASE / "board.db"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_urlsafe(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS", "").lower() in {"1", "true", "yes"},
    MAX_CONTENT_LENGTH=128 * 1024,
)


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(_=None):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE,
          email TEXT NOT NULL UNIQUE,
          password TEXT NOT NULL,
          is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS posts(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL,
          content TEXT NOT NULL,
          user_id INTEGER NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )
    exists = conn.execute("SELECT 1 FROM users WHERE id=1").fetchone()
    if not exists:
        pw = os.environ.get("ADMIN_PASSWORD", secrets.token_urlsafe(24))
        conn.execute(
            "INSERT INTO users(id, username, email, password, is_admin) VALUES(1, ?, ?, ?, 1)",
            ("admin", "admin@example.com", generate_password_hash(pw, method="scrypt")),
        )
    conn.commit()
    conn.close()


def wants_json():
    return request.is_json or "application/json" in request.headers.get("Accept", "")


def data():
    if request.is_json:
        obj = request.get_json(silent=True)
        return obj if isinstance(obj, dict) else {}
    return request.form.to_dict()


def out(payload, status=200, template=None, **ctx):
    if wants_json() or not template:
        return jsonify(payload), status
    return render_template(template, **ctx), status


def fail(msg, status=400):
    return out({"error": msg}, status, "error.html", error=msg)


def rowdict(row):
    return dict(row) if row else None


def csrf_token():
    session.setdefault("csrf", secrets.token_urlsafe(32))
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


def require_csrf():
    if request.method == "GET":
        return
    token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    if not token or not secrets.compare_digest(token, session.get("csrf", "")):
        return fail("invalid csrf token", 403)


@app.before_request
def load_user():
    if request.endpoint == "static":
        return
    g.user = None
    uid = session.get("uid")
    if uid:
        g.user = db().execute(
            "SELECT id, username, email, is_admin FROM users WHERE id=?", (uid,)
        ).fetchone()
    if request.method == "POST" and request.endpoint not in {"signup", "login"}:
        return require_csrf()


@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; base-uri 'self'; frame-ancestors 'none'"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def login_required(fn):
    @wraps(fn)
    def wrap(*a, **kw):
        if not g.user:
            return fail("login required", 401)
        return fn(*a, **kw)
    return wrap


def admin_required(fn):
    @wraps(fn)
    def wrap(*a, **kw):
        if not g.user:
            return fail("login required", 401)
        if not g.user["is_admin"]:
            return fail("admin required", 403)
        return fn(*a, **kw)
    return wrap


def valid_text(v, mn, mx):
    return isinstance(v, str) and mn <= len(v.strip()) <= mx


def post_rows(sql, args=()):
    rows = db().execute(sql, args).fetchall()
    return [dict(r) for r in rows]


@app.get("/")
def index():
    return redirect(url_for("posts"))


@app.post("/signup")
def signup():
    d = data()
    username = (d.get("username") or "").strip()
    email = (d.get("email") or "").strip().lower()
    password = d.get("password") or ""
    if not USERNAME_RE.fullmatch(username):
        return fail("invalid username")
    if not EMAIL_RE.fullmatch(email):
        return fail("invalid email")
    if len(password) < 12 or len(password) > 128:
        return fail("password must be 12-128 chars")
    try:
        cur = db().execute(
            "INSERT INTO users(username, email, password, is_admin) VALUES(?, ?, ?, 0)",
            (username, email, generate_password_hash(password, method="scrypt")),
        )
        db().commit()
    except sqlite3.IntegrityError:
        return fail("username or email exists", 409)
    return out({"id": cur.lastrowid, "username": username, "email": email}, 201)


@app.post("/login")
def login():
    d = data()
    ident = (d.get("username") or d.get("email") or "").strip().lower()
    password = d.get("password") or ""
    user = db().execute(
        "SELECT * FROM users WHERE lower(username)=? OR lower(email)=?", (ident, ident)
    ).fetchone()
    if not user or not check_password_hash(user["password"], password):
        return fail("invalid credentials", 401)
    session.clear()
    session["uid"] = user["id"]
    session["csrf"] = secrets.token_urlsafe(32)
    return out({"ok": True, "csrf_token": session["csrf"]})


@app.post("/logout")
@login_required
def logout():
    session.clear()
    return out({"ok": True})


@app.route("/posts", methods=["GET", "POST"])
def posts():
    if request.method == "POST":
        if not g.user:
            return fail("login required", 401)
        d = data()
        title = (d.get("title") or "").strip()
        content = (d.get("content") or "").strip()
        if not valid_text(title, 1, 120) or not valid_text(content, 1, 5000):
            return fail("invalid title or content")
        cur = db().execute(
            "INSERT INTO posts(title, content, user_id) VALUES(?, ?, ?)",
            (title, content, g.user["id"]),
        )
        db().commit()
        return out({"id": cur.lastrowid, "title": title, "content": content}, 201)
    rows = post_rows(
        """SELECT p.id, p.title, p.content, u.id AS author_id, u.username AS author
           FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC"""
    )
    return out({"posts": rows}, 200, "posts.html", posts=rows)


@app.get("/search")
def search():
    q = (request.args.get("q") or "").strip()
    if len(q) > 100:
        return fail("query too long")
    like = f"%{q}%"
    rows = post_rows(
        """SELECT p.id, p.title, p.content, u.id AS author_id, u.username AS author
           FROM posts p JOIN users u ON u.id=p.user_id
           WHERE p.title LIKE ? OR p.content LIKE ? ORDER BY p.id DESC""",
        (like, like),
    )
    return out({"q": q, "posts": rows}, 200, "posts.html", posts=rows)


@app.get("/users/<int:user_id>")
def user_profile(user_id):
    user = db().execute(
        "SELECT id, username, email FROM users WHERE id=?", (user_id,)
    ).fetchone()
    if not user:
        return fail("not found", 404)
    rows = post_rows(
        """SELECT p.id, p.title, p.content, u.id AS author_id, u.username AS author
           FROM posts p JOIN users u ON u.id=p.user_id
           WHERE p.user_id=? ORDER BY p.id DESC""",
        (user_id,),
    )
    payload = {"user": rowdict(user), "posts": rows}
    return out(payload, 200, "user.html", user=user, posts=rows)


@app.get("/admin")
@admin_required
def admin():
    stats = {
        "users": db().execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "posts": db().execute("SELECT COUNT(*) FROM posts").fetchone()[0],
    }
    return out(stats, 200, "admin.html", stats=stats)


@app.get("/admin/users")
@admin_required
def admin_users():
    users = post_rows("SELECT id, username, email, is_admin FROM users ORDER BY id")
    return out({"users": users}, 200, "admin_users.html", users=users)


@app.errorhandler(404)
def not_found(_):
    return fail("not found", 404)


@app.errorhandler(413)
def too_large(_):
    return fail("request too large", 413)


@app.errorhandler(500)
def server_error(_):
    return fail("server error", 500)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
