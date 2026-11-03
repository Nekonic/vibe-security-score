import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import time
import urllib.request
from collections import defaultdict, deque
from datetime import datetime, timedelta
from functools import wraps
from html import unescape
from pathlib import Path
from urllib.parse import urlparse

import sqlite3
from flask import (
    Flask,
    abort,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "app.db"
UPLOAD_DIR = BASE_DIR / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_NAME"] = "board_session"
app.config["JSON_SORT_KEYS"] = False


app.logger.setLevel(logging.INFO)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp"}
MAX_FILE_BYTES = 2 * 1024 * 1024
LOGIN_RATE_LIMITS = defaultdict(lambda: deque(maxlen=10))


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def log_security_event(event, user_id=None, username=None, ip=None, detail=None):
    app.logger.warning(
        json.dumps(
            {
                "event": event,
                "user_id": user_id,
                "username": username,
                "ip": ip,
                "detail": detail,
                "time": datetime.utcnow().isoformat(),
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )


def init_db():
    if DB_PATH.exists():
        DB_PATH.unlink()
    conn = get_conn()
    try:
        conn.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                phone TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                avatar_url TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                author_id INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                image_url TEXT,
                link_url TEXT,
                link_preview_title TEXT,
                link_preview_summary TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                author_id INTEGER NOT NULL,
                content TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_conn()
    try:
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?", (uid,)
        ).fetchone()
    finally:
        conn.close()
    return user


def is_admin_user():
    user = current_user()
    return bool(user and user["is_admin"])


def get_sorted_posts(sort):
    order = "created_at DESC"
    if sort == "oldest":
        order = "created_at ASC"
    elif sort == "title":
        order = "title COLLATE NOCASE ASC"
    query = f"SELECT p.*, u.username AS author FROM posts p JOIN users u ON p.author_id = u.id ORDER BY {order}"
    conn = get_conn()
    try:
        rows = conn.execute(query).fetchall()
    finally:
        conn.close()
    return [dict(row) for row in rows]


def parse_payload():
    if request.content_type and "application/json" in request.content_type:
        return request.get_json(silent=True) or {}
    if request.form:
        return request.form.to_dict()
    return {}

def wants_json():
    if request.is_json:
        return True
    accept = (request.headers.get("Accept") or "").lower()
    if "application/json" in accept and "text/html" not in accept:
        return True
    accept_m = request.accept_mimetypes
    return accept_m["application/json"] > accept_m["text/html"]


def hash_fingerprint(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def validate_phone(phone: str) -> bool:
    return bool(re.fullmatch(r"010\d{8}", phone or ""))


def validate_password(password: str) -> bool:
    if not password or len(password) < 8:
        return False
    if not re.search(r"[A-Za-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    return True


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def save_upload(file_obj):
    if not file_obj or file_obj.filename == "":
        return None
    if not allowed_file(file_obj.filename):
        abort(400, "Invalid file type")
    filename = secure_filename(file_obj.filename)
    ext = filename.rsplit(".", 1)[1].lower()
    new_name = f"{hash_fingerprint(f'{time.time_ns()}-{filename}')}.{ext}"
    data = file_obj.read()
    if len(data) > MAX_FILE_BYTES:
        abort(400, "File too large")
    file_obj.stream.seek(0)
    target = UPLOAD_DIR / new_name
    file_obj.save(target)
    return f"/static/uploads/{new_name}"


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = os.urandom(16).hex()
        session["csrf_token"] = token
    return token


def ensure_csrf():
    if request.path == "/logout":
        return
    user = current_user()
    if user is None:
        return
    token = request.form.get("_csrf") or request.headers.get("X-CSRF-Token")
    if not token or token != session.get("csrf_token"):
        abort(403, "CSRF token mismatch")


def rate_limit_login(identifier):
    q = LOGIN_RATE_LIMITS[identifier]
    now = time.time()
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= 5:
        abort(429, "Too many login attempts")
    q.append(now)


def secure_fetch_preview(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return None
        host = parsed.hostname
        if not host:
            return None
        infos = socket.getaddrinfo(host, parsed.port or 80, proto=socket.IPPROTO_TCP)
        blocked = False
        for family, _, _, _, sockaddr in infos:
            ip = ipaddress.ip_address(sockaddr[0])
            if (
                ip.is_loopback
                or ip.is_private
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_link_local
            ):
                blocked = True
                break
        if blocked:
            return None
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={"User-Agent": "secure-board/1.0"})
        with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:
            if resp.status != 200:
                return None
            raw = resp.read(120000).decode("utf-8", errors="ignore")
        title = None
        summary = None
        m = re.search(r"<title[^>]*>(.*?)</title>", raw, re.IGNORECASE | re.S)
        if m:
            title = re.sub(r"\s+", " ", unescape(re.sub("<[^>]+>", "", m.group(1).strip())))
        d = re.search(
            r"<meta\s+name=[\"']description[\"'][^>]*content=[\"'](.*?)[\"']",
            raw,
            re.IGNORECASE | re.S,
        )
        if d:
            summary = re.sub(r"\s+", " ", unescape(d.group(1).strip()))
        return {
            "link_title": (title or "")[:200],
            "link_summary": (summary or "")[:400],
        }
    except Exception:
        return None


def user_has_post_access(pid, user_id):
    if is_admin_user():
        return True
    return pid == user_id


def _fetch_post(post_id):
    conn = get_conn()
    try:
        post = conn.execute(
            """SELECT p.*, u.username AS author
               FROM posts p
               JOIN users u ON p.author_id = u.id
               WHERE p.id = ?""",
            (post_id,),
        ).fetchone()
        if not post:
            return None
        comments = conn.execute(
            """SELECT c.*, u.username AS author
               FROM comments c
               JOIN users u ON c.author_id = u.id
               WHERE c.post_id = ?
               ORDER BY c.id DESC""",
            (post_id,),
        ).fetchall()
        return dict(post), [dict(c) for c in comments]
    finally:
        conn.close()


def json_or_html(data, template=None, status=200, **context):
    if wants_json():
        return make_response(jsonify(data), status)
    if template is None:
        return make_response(jsonify(data), status)
    return make_response(render_template(template, **context), status)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            if wants_json():
                return make_response(jsonify({"error": "login required"}), 401)
            return render_template(
                "login.html",
                error="login required",
                csrf_token=csrf_token(),
            )
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            abort(401)
        if not is_admin_user():
            abort(403)
        return fn(*args, **kwargs)

    return wrapper


def require_ownership(owner_id):
    if not current_user():
        abort(401)
    if not (is_admin_user() or current_user()["id"] == owner_id):
        abort(403)


@app.after_request
def apply_security_headers(resp):
    resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["X-XSS-Protection"] = "0"
    resp.headers[
        "Content-Security-Policy"
    ] = "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; base-uri 'self'; frame-ancestors 'none'"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    return resp


@app.before_request
def ensure_csrf_token():
    csrf_token()


@app.route("/")
def index():
    return redirect("/posts")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html", csrf_token=csrf_token())

    data = parse_payload()
    username = (data.get("username") or "").strip()
    phone = (data.get("phone") or "").strip()
    password = data.get("password") or ""
    if not username or not phone or not password:
            return json_or_html({"error": "required fields"}, "signup.html", 400, error="required fields", csrf_token=csrf_token())
    if not validate_phone(phone) or not validate_password(password):
            return json_or_html(
                {"error": "invalid username, phone, or password"},
                "signup.html",
                400,
                error="invalid username, phone, or password",
                csrf_token=csrf_token(),
            )

    conn = get_conn()
    try:
        users_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        is_admin = 1 if users_count == 0 else 0
        pw = generate_password_hash(password)
        try:
            cur = conn.execute(
                "INSERT INTO users(username, phone, password, is_admin) VALUES (?, ?, ?, ?)",
                (username, phone, pw, is_admin),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return json_or_html(
                {"error": "duplicate username or phone"},
                "signup.html",
                409,
                error="duplicate username or phone",
                csrf_token=csrf_token(),
            )
        user_id = cur.lastrowid
    finally:
        conn.close()
    session.clear()
    session["user_id"] = user_id
    session["username"] = username
    log_security_event("signup", user_id=user_id, username=username, ip=request.remote_addr)
    return json_or_html(
        {"message": "signup ok", "user_id": user_id, "csrf_token": csrf_token()},
        "posts.html",
        201,
        posts=get_sorted_posts("newest"),
        sort="newest",
        query="",
        csrf_token=csrf_token(),
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", csrf_token=csrf_token())

    key = request.remote_addr or ""
    rate_limit_login(key)
    data = parse_payload()
    username_or_phone = (data.get("username") or data.get("phone") or "").strip()
    password = data.get("password") or ""
    if not username_or_phone or not password:
        return json_or_html(
            {"error": "required fields"},
            "login.html",
            400,
            error="required fields",
            csrf_token=csrf_token(),
        )
    conn = get_conn()
    try:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? OR phone = ?",
            (username_or_phone, username_or_phone),
        ).fetchone()
    finally:
        conn.close()
    if not user or not check_password_hash(user["password"], password):
        log_security_event(
            "login_failed",
            user_id=user["id"] if user else None,
            username=username_or_phone,
            ip=request.remote_addr,
        )
        return json_or_html(
            {"error": "invalid credentials"},
            "login.html",
            401,
            error="invalid credentials",
            csrf_token=csrf_token(),
        )
    LOGIN_RATE_LIMITS[key].clear()
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    log_security_event("login_success", user_id=user["id"], username=user["username"], ip=request.remote_addr)
    payload = {"message": "login ok", "user": {"id": user["id"], "username": user["username"]}, "csrf_token": csrf_token()}
    return json_or_html(
        payload,
        "posts.html",
        200,
        posts=get_sorted_posts("newest"),
        sort="newest",
        query="",
        logged_in=True,
        csrf_token=csrf_token(),
        user=user,
    )


@app.route("/logout", methods=["POST"])
def logout():
    ensure_csrf()
    session.clear()
    return json_or_html({"message": "logout ok"}, "login.html", 200, csrf_token=csrf_token())


@app.route("/account/password", methods=["POST"])
@login_required
def account_password():
    ensure_csrf()
    data = parse_payload()
    old_password = data.get("old_password") or ""
    new_password = data.get("new_password") or ""
    user = current_user()
    if not old_password or not new_password:
        return json_or_html({"error": "required fields"}, status=400)
    if not validate_password(new_password):
        return json_or_html({"error": "weak password"}, status=400)
    conn = get_conn()
    try:
        row = conn.execute("SELECT password FROM users WHERE id = ?", (user["id"],)).fetchone()
        if not check_password_hash(row["password"], old_password):
            return json_or_html({"error": "wrong old password"}, status=403)
        conn.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (generate_password_hash(new_password), user["id"]),
        )
        conn.commit()
    finally:
        conn.close()
    log_security_event("password_change", user_id=user["id"], username=user["username"], ip=request.remote_addr)
    return json_or_html({"message": "password updated"}, status=200)


@app.route("/posts", methods=["GET", "POST"])
def posts():
    if request.method == "GET":
        sort = request.args.get("sort", "newest")
        if sort not in {"newest", "oldest", "title"}:
            sort = "newest"
        return json_or_html(
            {"posts": get_sorted_posts(sort)},
            "posts.html",
            200,
            posts=get_sorted_posts(sort),
            sort=sort,
            query="",
            csrf_token=session.get("csrf_token"),
            user=current_user(),
            logged_in=bool(current_user()),
        )

    ensure_csrf()
    user = current_user()
    if not user:
        return json_or_html({"error": "login required"}, status=401)
    data = parse_payload()
    title = (data.get("title") or "").strip()
    content = (data.get("content") or "").strip()
    if not title or not content:
        return json_or_html({"error": "required fields"}, status=400)
    link_url = (data.get("link_url") or "").strip()
    preview = secure_fetch_preview(link_url) if link_url else None
    image_url = save_upload(request.files.get("image"))
    conn = get_conn()
    try:
        conn.execute(
            """INSERT INTO posts(title, content, author_id, image_url, link_url, link_preview_title, link_preview_summary)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                title,
                content,
                user["id"],
                image_url,
                link_url,
                preview["link_title"] if preview else None,
                preview["link_summary"] if preview else None,
            ),
        )
        conn.commit()
        pid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    finally:
        conn.close()
    log_security_event("post_created", user_id=user["id"], username=user["username"], ip=request.remote_addr)
    return json_or_html(
        {"message": "post created", "post_id": pid},
        "post_detail.html",
        201,
        post=_fetch_post(pid)[0],
        comments=[],
        csrf_token=csrf_token(),
        user=user,
        logged_in=True,
    )


@app.route("/search", methods=["GET"])
def search():
    q = (request.args.get("q") or "").strip()
    sort = request.args.get("sort", "newest")
    if sort not in {"newest", "oldest", "title"}:
        sort = "newest"
    order = {
        "newest": "created_at DESC",
        "oldest": "created_at ASC",
        "title": "title COLLATE NOCASE ASC",
    }[sort]
    if not q:
        results = []
    else:
        conn = get_conn()
        try:
            results = conn.execute(
                f"""
                SELECT p.*, u.username AS author
                FROM posts p
                JOIN users u ON p.author_id = u.id
                WHERE p.title LIKE ? OR p.content LIKE ?
                ORDER BY {order}
                """,
                (f"%{q}%", f"%{q}%"),
            ).fetchall()
        finally:
            conn.close()
        results = [dict(r) for r in results]
    if wants_json():
        return jsonify({"q": q, "results": results, "count": len(results)})
    return render_template(
        "posts.html",
        posts=results,
        sort=sort,
        query=q,
        csrf_token=csrf_token(),
        logged_in=bool(current_user()),
        user=current_user(),
    )


@app.route("/posts/<int:pid>", methods=["GET", "PUT", "PATCH", "DELETE"])
def post_detail(pid):
    post_data = _fetch_post(pid)
    if not post_data:
        abort(404)
    post, comments = post_data
    if request.method == "GET":
        if wants_json():
            return jsonify({"post": post, "comments": comments})
        return render_template(
            "post_detail.html",
            post=post,
            comments=comments,
            csrf_token=csrf_token(),
            logged_in=bool(current_user()),
            user=current_user(),
        )

    ensure_csrf()
    user = current_user()
    if not user:
        abort(401)
    if not (is_admin_user() or user["id"] == post["author_id"]):
        abort(403)

    if request.method in {"PUT", "PATCH"}:
        data = parse_payload()
        title = (data.get("title") or "").strip()
        content = (data.get("content") or "").strip()
        if not title or not content:
            return json_or_html({"error": "required fields"}, status=400)
        conn = get_conn()
        try:
            conn.execute(
                "UPDATE posts SET title = ?, content = ? WHERE id = ?",
                (title, content, pid),
            )
            conn.commit()
        finally:
            conn.close()
        log_security_event("post_updated", user_id=user["id"], username=user["username"], ip=request.remote_addr, detail=f"post_id={pid}")
        return json_or_html({"message": "post updated"}, status=200)

    conn = get_conn()
    try:
        conn.execute("DELETE FROM comments WHERE post_id = ?", (pid,))
        conn.execute("DELETE FROM posts WHERE id = ?", (pid,))
        conn.commit()
    finally:
        conn.close()
    log_security_event("post_deleted", user_id=user["id"], username=user["username"], ip=request.remote_addr, detail=f"post_id={pid}")
    return json_or_html({"message": "post deleted"}, status=200)


@app.route("/posts/<int:pid>/comments", methods=["POST"])
@login_required
def post_comments(pid):
    ensure_csrf()
    if not _fetch_post(pid):
        abort(404)
    data = parse_payload()
    content = (data.get("content") or "").strip()
    if not content:
        return json_or_html({"error": "content required"}, status=400)
    user = current_user()
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO comments(post_id, author_id, content) VALUES (?, ?, ?)",
            (pid, user["id"], content),
        )
        conn.commit()
    finally:
        conn.close()
    log_security_event("comment_created", user_id=user["id"], username=user["username"], ip=request.remote_addr, detail=f"post_id={pid}")
    return json_or_html({"message": "comment created"}, "post_detail.html", 201, **({
        "post": _fetch_post(pid)[0],
        "comments": _fetch_post(pid)[1],
        "csrf_token": csrf_token(),
        "logged_in": True,
        "user": user,
    }))


@app.route("/comments/<int:cid>", methods=["PUT", "PATCH", "DELETE"])
@login_required
def comment_detail(cid):
    ensure_csrf()
    user = current_user()
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM comments WHERE id = ?",
            (cid,),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        abort(404)
    if not (is_admin_user() or user["id"] == row["author_id"]):
        abort(403)
    if request.method in {"PUT", "PATCH"}:
        data = parse_payload()
        content = (data.get("content") or "").strip()
        if not content:
            return json_or_html({"error": "content required"}, status=400)
        conn = get_conn()
        try:
            conn.execute(
                "UPDATE comments SET content = ? WHERE id = ?",
                (content, cid),
            )
            conn.commit()
        finally:
            conn.close()
        return json_or_html({"message": "comment updated"}, status=200)
    conn = get_conn()
    try:
        conn.execute("DELETE FROM comments WHERE id = ?", (cid,))
        conn.commit()
    finally:
        conn.close()
    return json_or_html({"message": "comment deleted"}, status=200)


@app.route("/users/<int:uid>", methods=["GET"])
def user_profile(uid):
    conn = get_conn()
    try:
        user = conn.execute("SELECT id, username, phone, avatar_url FROM users WHERE id = ?", (uid,)).fetchone()
        posts = conn.execute(
            """SELECT p.*, u.username AS author
               FROM posts p
               JOIN users u ON p.author_id = u.id
               WHERE p.author_id = ?
               ORDER BY p.id DESC""",
            (uid,),
        ).fetchall()
    finally:
        conn.close()
    if not user:
        abort(404)
    viewer = current_user()
    data = {
        "id": user["id"],
        "username": user["username"],
        "avatar_url": user["avatar_url"],
        "phone": user["phone"] if viewer and viewer["id"] == uid else None,
        "posts": [dict(row) for row in posts],
    }
    if wants_json():
        return jsonify(data)
    data["viewer"] = viewer
    return render_template(
        "user_profile.html",
        user=data,
        csrf_token=session.get("csrf_token"),
        logged_in=bool(viewer),
    )


@app.route("/profile/avatar", methods=["POST"])
@login_required
def profile_avatar():
    ensure_csrf()
    user = current_user()
    payload = parse_payload()
    avatar_url = payload.get("avatar_url")
    file_url = save_upload(request.files.get("image"))
    final_url = file_url or (avatar_url.strip() if avatar_url else None)
    if not final_url:
        return json_or_html({"error": "image or avatar_url required"}, status=400)
    if avatar_url and not (avatar_url.startswith("http://") or avatar_url.startswith("https://")):
        return json_or_html({"error": "invalid avatar_url"}, status=400)
    conn = get_conn()
    try:
        conn.execute(
            "UPDATE users SET avatar_url = ? WHERE id = ?",
            (final_url, user["id"]),
        )
        conn.commit()
    finally:
        conn.close()
    return json_or_html(
        {"message": "avatar updated", "avatar_url": final_url, "image_url": final_url, "url": final_url},
        status=200,
    )


@app.route("/admin", methods=["GET"])
@admin_required
def admin_home():
    return render_template(
        "admin_home.html",
        user=current_user(),
        csrf_token=session.get("csrf_token"),
    )


@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_users():
    conn = get_conn()
    try:
        users = conn.execute("SELECT id, username, phone, is_admin, avatar_url FROM users ORDER BY id ASC").fetchall()
    finally:
        conn.close()
    if wants_json():
        return jsonify({"users": [dict(u) for u in users]})
    return render_template(
        "admin_users.html",
        users=[dict(u) for u in users],
        csrf_token=session.get("csrf_token"),
    )


@app.route("/admin/users/<int:uid>/role", methods=["POST"])
@admin_required
def admin_set_role(uid):
    ensure_csrf()
    data = parse_payload()
    role = (data.get("role") or "").strip().lower()
    if role not in {"admin", "user"}:
        return json_or_html({"error": "invalid role"}, status=400)
    is_admin = 1 if role == "admin" else 0
    conn = get_conn()
    try:
        conn.execute("UPDATE users SET is_admin = ? WHERE id = ?", (is_admin, uid))
        conn.commit()
    finally:
        conn.close()
    return json_or_html({"message": "role updated"}, status=200)


@app.route("/admin/users/<int:uid>", methods=["DELETE"])
@admin_required
def admin_delete_user(uid):
    if uid == current_user()["id"]:
        abort(403)
    conn = get_conn()
    try:
        conn.execute("DELETE FROM users WHERE id = ?", (uid,))
        conn.commit()
    finally:
        conn.close()
    return json_or_html({"message": "user deleted"}, status=200)


@app.errorhandler(403)
def forbid(e):
    if wants_json():
        return jsonify({"error": "forbidden"}), 403
    return render_template("error.html", message="forbidden", code=403, csrf_token=session.get("csrf_token")), 403


@app.errorhandler(404)
def not_found(e):
    if wants_json():
        return jsonify({"error": "not found"}), 404
    return render_template("error.html", message="not found", code=404, csrf_token=session.get("csrf_token")), 404


@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(405)
@app.errorhandler(429)
def bad_request(e):
    if wants_json():
        return jsonify({"error": str(e)}), e.code or 400
    return render_template("error.html", message=str(e), code=e.code or 400, csrf_token=session.get("csrf_token")), e.code or 400


if __name__ == "__main__":
    init_db()
    app.run()
