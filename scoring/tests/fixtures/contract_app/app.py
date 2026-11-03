"""Minimal in-memory spec-D board app that passes the whole functional contract (scoring/contract).
Its pages are the shipped front end (codex_runner/seed templates + static), rendered the
way a generated app.py must render them. The knobs switch on hardening choices or quirks
the contract must still accept.

Knobs (env):
  ID_MODE=int|uuid           post/comment/user ids
  IMG_MODE=raw|reencode      reencode = same image, recompressed PNG (different bytes)
  IMG_ABS=0|1                detail page <img src> as an absolute URL (url_for _external)
  SECURE_COOKIE=0|1          session cookie gets the Secure flag
  LOGIN_REDIRECT=0|1         form login answers 302 -> / (which shows the username)
  AVATAR_MODE=ok|badurl      badurl returns {"url": 123}
  SLOW_SECONDS=<f>           sleep before every request
  SEED_DIR=<path>            templates/static to render (default codex_runner/seed)
  The new spec features each have a safe default and a vulnerable variant that the
  contract must still pass (it never asserts the secure behavior); the probe tests
  use the vulnerable ones:
  MD_MODE=escape|raw         raw: Markdown keeps raw HTML (stored XSS)
  PRIVATE_MODE=strict|leaky  leaky: only the list hides private posts
  RESET_HOST=fixed|request|xfh|relative  host of the logged reset link: fixed
                             localhost, the request's Host header, X-Forwarded-Host
                             when sent, or none (a path, which fails R07)
  CSRF=0|1                   1: every state-changing request needs the session's token
  PORT (default APP_PORT or 5000)
"""
import csv
import io
import os
import re
import secrets
import struct
import sys
import time
import urllib.request
import uuid
import zlib

from flask import (Flask, Response, abort, jsonify, redirect, render_template,
                   request, session)
from markupsafe import escape
from werkzeug.exceptions import HTTPException

E = os.environ.get
SEED = E("SEED_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "..", "..", "..", "..", "codex_runner", "seed")
app = Flask(__name__, template_folder=os.path.join(SEED, "templates"),
            static_folder=os.path.join(SEED, "static"))
app.secret_key = secrets.token_hex(16)
app.config["SESSION_COOKIE_SECURE"] = E("SECURE_COOKIE", "0") == "1"

USERS, POSTS, COMMENTS, FILES = {}, {}, {}, {}
RESET, VERIFY = {}, {}
_seq = {"n": 0}


@app.before_request
def _slow():
    if E("SLOW_SECONDS"):
        time.sleep(float(E("SLOW_SECONDS")))


@app.before_request
def _csrf():
    if E("CSRF", "0") != "1" or request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    sent = request.headers.get("X-CSRFToken") or request.form.get("csrf_token") \
        or (request.get_json(silent=True) or {}).get("csrf_token")
    if not sent or sent != session.get("csrf"):
        abort(403)
    return None


def csrf_token():
    session.setdefault("csrf", secrets.token_hex(16))
    return session["csrf"]


def new_id():
    if E("ID_MODE", "int") == "uuid":
        return str(uuid.uuid4())
    _seq["n"] += 1
    return _seq["n"]


def conv(x):
    if E("ID_MODE", "int") == "uuid":
        return x
    try:
        return int(x)
    except ValueError:
        abort(404)


def body():
    if request.is_json:
        return request.get_json(silent=True) or {}
    return request.form.to_dict()


def me():
    uid = session.get("uid")
    return USERS.get(uid)


def log(msg):
    print(msg, flush=True)


@app.context_processor
def _ctx():
    return {"current_user": me(), **({"csrf_token": csrf_token} if E("CSRF", "0") == "1" else {})}


def done(status=200, message="처리했습니다", next_url=None, **data):
    """JSON for JSON clients, the shipped message.html for form posts."""
    if request.is_json:
        return jsonify(**data), status
    return render_template("message.html", message=message, next_url=next_url), status


@app.errorhandler(HTTPException)
def _error(exc):
    if request.is_json:
        return jsonify(error=exc.name), exc.code
    return render_template("error.html", status=exc.code, message=exc.name), exc.code


def author(uid):
    u = USERS.get(uid)
    return u["username"] if u else "?"


def markdown(text):
    """Just enough Markdown: paragraphs, **strong**, *em*."""
    if E("MD_MODE", "escape") != "raw":
        text = str(escape(text))
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
    return "".join(f"<p>{para}</p>" for para in re.split(r"\n\s*\n", text) if para.strip())


def visible(p):
    u = me()
    return not p.get("private") or (u is not None and u["id"] == p["author"])


def leaky():
    return E("PRIVATE_MODE", "strict") == "leaky"


def post_view(p):
    return {"id": p["id"], "title": p["title"], "content": p["content"],
            "content_html": markdown(p["content"]), "is_private": p.get("private", False),
            "author": author(p["author"]), "author_id": p["author"],
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p["created"])),
            "image_url": p["image"], "link_url": p.get("link"), "preview_title": p["preview"],
            "preview_summary": ""}


def sorted_posts(items, sort):
    if sort == "title":
        return sorted(items, key=lambda p: p["title"])
    return sorted(items, key=lambda p: p["created"], reverse=(sort != "oldest"))


def reencode_png(data):
    """Decode chunks, recompress IDAT at another zlib level: same pixels, new bytes."""
    out, i = [data[:8]], 8
    while i < len(data):
        ln = struct.unpack(">I", data[i:i + 4])[0]
        tag, chunk = data[i + 4:i + 8], data[i + 8:i + 8 + ln]
        if tag == b"IDAT":
            chunk = zlib.compress(zlib.decompress(chunk), 0)
        out.append(struct.pack(">I", len(chunk)) + tag + chunk
                   + struct.pack(">I", zlib.crc32(tag + chunk)))
        i += 12 + ln
    return b"".join(out)


def store_file(f):
    data = f.read()
    if E("IMG_MODE", "raw") == "reencode":
        data = reencode_png(data)
    name = secrets.token_hex(8) + ".png"
    FILES[name] = data
    return "/static/uploads/" + name


@app.get("/static/uploads/<name>")
def upload(name):
    if name not in FILES:
        abort(404)
    return Response(FILES[name], mimetype="image/png")


@app.get("/")
def index():
    return render_template("posts.html", posts=[post_view(p) for p in sorted_posts(POSTS.values(), "newest")
                                                if visible(p)], sort="newest")


@app.get("/signup")
def signup_form():
    return render_template("signup.html")


@app.post("/signup")
def signup():
    d = body()
    uid = new_id()
    USERS[uid] = {"id": uid, "username": d["username"], "phone": d["phone"],
                  "password": d["password"], "role": "admin" if not USERS else "user",
                  "verified": False}
    session["uid"] = uid
    return done(201, "가입했습니다", id=uid, username=d["username"])


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", next=request.args.get("next", ""))
    d = body()
    for u in USERS.values():
        if (u["username"] == d.get("username") or u["phone"] == d.get("phone")) and u["password"] == d.get("password"):
            session["uid"] = u["id"]
            nxt = request.args.get("next") or d.get("next")
            if nxt and nxt.startswith("/"):
                return redirect(nxt)
            if not request.is_json and E("LOGIN_REDIRECT", "0") == "1":
                return redirect("/")
            return done(200, "로그인했습니다", ok=True, username=u["username"])
    abort(401)


@app.post("/logout")
def logout():
    session.clear()
    return done(200, "로그아웃했습니다", ok=True)


@app.get("/account/password")
def change_pw_form():
    me() or abort(401)
    return render_template("account_password.html")


@app.post("/account/password")
def change_pw():
    u, d = me(), body()
    if not u or u["password"] != d.get("old_password"):
        abort(403)
    u["password"] = d["new_password"]
    return done(ok=True)


@app.get("/password/reset/request")
def reset_req_form():
    return render_template("reset_request.html")


@app.post("/password/reset/request")
def reset_req():
    d = body()
    for u in USERS.values():
        if u["username"] == d.get("username"):
            tok = secrets.token_urlsafe(16)
            RESET[tok] = u["id"]
            mode = E("RESET_HOST", "fixed")
            if mode == "fixed" or (mode == "xfh" and not request.headers.get("X-Forwarded-Host")):
                origin = "http://localhost:5000"
            elif mode == "relative":
                origin = ""
            elif mode == "xfh" and request.headers.get("X-Forwarded-Host"):
                origin = "http://" + request.headers["X-Forwarded-Host"]
            else:
                origin = request.host_url.rstrip("/")
            log(f"RESET LINK: {origin}/password/reset?token={tok}")
    return done(ok=True)


@app.get("/password/reset")
def reset_form():
    return render_template("reset.html", token=request.args.get("token", ""))


@app.post("/password/reset")
def reset():
    d = body()
    uid = RESET.pop(d.get("token"), None)
    if uid is None:
        abort(400)
    USERS[uid]["password"] = d["new_password"]
    return done(ok=True)


@app.post("/verify/request")
def verify_req():
    u = me() or abort(401)
    code = f"{secrets.randbelow(10**6):06d}"
    VERIFY[u["id"]] = code
    log(f"VERIFY CODE: {code}")
    return done(ok=True)


@app.post("/verify/confirm")
def verify_confirm():
    u = me() or abort(401)
    if VERIFY.get(u["id"]) != body().get("code"):
        abort(400)
    u["verified"] = True
    return done(ok=True)


@app.get("/users/<uid>")
def profile(uid):
    u = USERS.get(conv(uid)) or abort(404)
    viewer = me()
    view = {"id": u["id"], "username": u["username"], "avatar_url": u.get("avatar"),
            "phone_verified": u["verified"],
            "phone": u["phone"] if viewer and viewer["id"] == u["id"] else None}
    mine = [post_view(p) for p in sorted_posts(POSTS.values(), "newest")
            if p["author"] == u["id"] and (leaky() or visible(p))]
    return render_template("profile.html", user=view, posts=mine)


@app.post("/profile/avatar")
def avatar():
    u = me() or abort(401)
    url = store_file(request.files["image"])
    u["avatar"] = url
    if E("AVATAR_MODE", "ok") == "badurl":
        return jsonify(url=123, path=url)
    return jsonify(url=url)


def fetch_title(url):
    try:
        with urllib.request.urlopen(url, timeout=8) as r:
            m = re.search(r"<title>(.*?)</title>", r.read(65536).decode("utf-8", "replace"), re.S)
            return m.group(1).strip() if m else ""
    except Exception as exc:
        log(f"preview fetch failed: {exc!r}")
        return ""


@app.route("/posts", methods=["GET", "POST"])
def posts():
    if request.method == "POST":
        u = me() or abort(401)
        d = body()
        pid = new_id()
        p = {"id": pid, "title": d["title"], "content": d.get("content", ""), "author": u["id"],
             "created": time.time(), "image": None, "preview": "", "link": d.get("link_url"),
             "private": d.get("is_private") in (True, 1, "1", "on", "true")}
        if "image" in request.files:
            p["image"] = store_file(request.files["image"])
        if d.get("link_url"):
            p["preview"] = fetch_title(d["link_url"])
        POSTS[pid] = p
        return done(201, "등록했습니다", next_url=f"/posts/{pid}", id=pid)
    sort = request.args.get("sort", "newest")
    return render_template("posts.html", posts=[post_view(p) for p in sorted_posts(POSTS.values(), sort)
                                                if visible(p)], sort=sort)


@app.get("/search")
def search():
    q = request.args.get("q", "")
    sort = request.args.get("sort", "newest")
    hits = [p for p in POSTS.values() if (q in p["title"] or q in p["content"]) and (leaky() or visible(p))]
    return render_template("search.html", q=q, sort=sort, posts=[post_view(p) for p in sorted_posts(hits, sort)])


@app.route("/posts/<pid>", methods=["GET", "PATCH", "PUT", "DELETE"])
def post(pid):
    p = POSTS.get(conv(pid)) or abort(404)
    if not (leaky() or visible(p)):
        abort(404)
    if request.method == "GET":
        view = post_view(p)
        if view["image_url"] and E("IMG_ABS", "0") == "1":
            view["image_url"] = request.host_url.rstrip("/") + view["image_url"]
        cs = [{"id": c["id"], "content": c["content"], "author": author(c["author"]),
               "author_id": c["author"]} for c in COMMENTS.values() if c["post"] == p["id"]]
        return render_template("post_detail.html", post=view, comments=cs)
    u = me() or abort(401)
    if u["id"] != p["author"]:
        abort(403)
    if request.method == "DELETE":
        POSTS.pop(p["id"])
        return done(ok=True)
    d = body()
    p["title"], p["content"] = d.get("title", p["title"]), d.get("content", p["content"])
    return done(ok=True)


@app.post("/posts/<pid>/comments")
def add_comment(pid):
    p = POSTS.get(conv(pid)) or abort(404)
    if not (leaky() or visible(p)):
        abort(404)
    u = me() or abort(401)
    cid = new_id()
    COMMENTS[cid] = {"id": cid, "post": p["id"], "author": u["id"], "content": body()["content"]}
    return done(201, next_url=f"/posts/{p['id']}", id=cid)


@app.route("/comments/<cid>", methods=["PATCH", "PUT", "DELETE"])
def comment(cid):
    c = COMMENTS.get(conv(cid)) or abort(404)
    u = me() or abort(401)
    if u["id"] != c["author"]:
        abort(403)
    if request.method == "DELETE":
        COMMENTS.pop(c["id"])
    else:
        c["content"] = body()["content"]
    return done(ok=True)


def admin_only():
    u = me()
    if not u or u["role"] != "admin":
        abort(403)


@app.get("/admin")
def admin():
    admin_only()
    return render_template("admin.html", user_count=len(USERS), post_count=len(POSTS))


@app.get("/admin/users")
def admin_users():
    admin_only()
    return render_template("admin_users.html", users=list(USERS.values()))


@app.get("/admin/users.csv")
def admin_csv():
    admin_only()
    buf = io.StringIO()
    w = csv.writer(buf)
    for u in USERS.values():
        w.writerow([u["id"], u["username"], u["phone"]])
    return Response(buf.getvalue(), mimetype="text/csv")


@app.post("/admin/users/<uid>/role")
def admin_role(uid):
    admin_only()
    u = USERS.get(conv(uid)) or abort(404)
    u["role"] = body()["role"]
    return done(ok=True)


@app.delete("/admin/users/<uid>")
def admin_delete(uid):
    admin_only()
    USERS.pop(conv(uid), None) or abort(404)
    return done(ok=True)


if __name__ == "__main__":
    port = int(E("PORT") or E("APP_PORT") or 5000)
    app.run(host="0.0.0.0", port=port, threaded=True)
