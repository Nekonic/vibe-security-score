import csv
import hashlib
import html
import io
import os
import re
import secrets
import sqlite3
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from functools import wraps

import bleach
import markdown
from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)), MAX_CONTENT_LENGTH=8 * 1024 * 1024)
DB_PATH = os.path.join(os.path.dirname(__file__), "board.sqlite3")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
RESET_SERIALIZER = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="password-reset")


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    con = db()
    con.executescript("""
    CREATE TABLE user (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, phone TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0, avatar_url TEXT, phone_verified INTEGER NOT NULL DEFAULT 0,
      points INTEGER NOT NULL DEFAULT 100, signature TEXT);
    CREATE TABLE post (id INTEGER PRIMARY KEY, title TEXT NOT NULL, content TEXT NOT NULL, author_id INTEGER NOT NULL,
      created_at TEXT NOT NULL, image_url TEXT, link_url TEXT, is_private INTEGER NOT NULL DEFAULT 0,
      preview_title TEXT, preview_summary TEXT, FOREIGN KEY(author_id) REFERENCES user(id) ON DELETE CASCADE);
    CREATE TABLE comment (id INTEGER PRIMARY KEY, post_id INTEGER NOT NULL, author_id INTEGER NOT NULL, content TEXT NOT NULL,
      FOREIGN KEY(post_id) REFERENCES post(id) ON DELETE CASCADE, FOREIGN KEY(author_id) REFERENCES user(id) ON DELETE CASCADE);
    """)
    con.commit(); con.close()


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


@app.context_processor
def context():
    return {"current_user": current_user(), "csrf_token": csrf_token()}


def current_user():
    uid = session.get("user_id")
    if not uid: return None
    con = db(); user = con.execute("SELECT * FROM user WHERE id=?", (uid,)).fetchone(); con.close()
    return user


def wants_json():
    return request.is_json or request.accept_mimetypes.best == "application/json"


def reply(message, status=200, next_url="/posts"):
    if wants_json(): return jsonify({"message": message}), status
    return render_template("message.html", message=message, next_url=next_url), status


def fail(message, status=400):
    if wants_json(): return jsonify({"error": message}), status
    return render_template("error.html", status=status, message=message), status


def data(): return request.get_json(silent=True) or request.form


def check_csrf():
    supplied = request.headers.get("X-CSRFToken") or request.form.get("csrf_token") or (request.get_json(silent=True) or {}).get("csrf_token")
    return supplied and secrets.compare_digest(str(supplied), str(session.get("csrf", "")))


@app.before_request
def security():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not check_csrf():
        return fail("CSRF 토큰이 올바르지 않습니다", 403)


def login_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not current_user(): return fail("로그인이 필요합니다", 401)
        return fn(*a, **kw)
    return wrapped


def admin_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        u = current_user()
        if not u or not u["is_admin"]: return fail("관리자만 이용할 수 있습니다", 403)
        return fn(*a, **kw)
    return wrapped


def password_hash(value): return hashlib.scrypt(value.encode(), salt=app.config["SECRET_KEY"].encode()[:32], n=2**14, r=8, p=1).hex()
def password_ok(value, stored):
    try: return secrets.compare_digest(password_hash(value), stored)
    except (ValueError, TypeError): return False


def row_post(row):
    d = dict(row); d["author"] = d.pop("username", ""); return d


def posts_query(where="1=1", args=(), sort="newest"):
    order = {"newest": "p.id DESC", "oldest": "p.id ASC", "title": "p.title COLLATE NOCASE ASC"}.get(sort, "p.id DESC")
    con = db(); rows = con.execute(f"SELECT p.*, u.username FROM post p JOIN user u ON u.id=p.author_id WHERE {where} ORDER BY {order}", args).fetchall(); con.close()
    return [row_post(r) for r in rows]


def save_upload(file):
    if not file or not file.filename: return None
    name = secure_filename(file.filename)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED_EXTENSIONS: raise ValueError("지원하지 않는 이미지 형식입니다")
    filename = f"{uuid.uuid4().hex}.{ext}"; path = os.path.join(UPLOAD_DIR, filename); file.save(path)
    return f"/static/uploads/{filename}"


def preview(url):
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"}: return "", ""
        req = urllib.request.Request(url, headers={"User-Agent": "BoardPreview/1.0"})
        with urllib.request.urlopen(req, timeout=3) as res: raw = res.read(100000).decode("utf-8", "ignore")
        title = re.search(r"<title[^>]*>(.*?)</title>", raw, re.I | re.S)
        desc = re.search(r'<meta[^>]+(?:name|property)=["\'](?:description|og:description)["\'][^>]+content=["\'](.*?)["\']', raw, re.I | re.S)
        return ((html.unescape(re.sub(r"<.*?>", "", title.group(1))).strip() if title else ""), (html.unescape(desc.group(1)).strip() if desc else "")[:500])
    except Exception: return "", ""


def safe_md(text):
    raw = markdown.markdown(text, extensions=["extra", "nl2br"])
    return bleach.clean(raw, tags=["p", "br", "strong", "em", "ul", "ol", "li", "h1", "h2", "h3", "blockquote", "code", "pre", "a"], attributes={"a": ["href", "title", "rel"]}, protocols=["http", "https", "mailto"])


@app.get("/signup")
def signup_page(): return render_template("signup.html")

@app.post("/signup")
def signup():
    d = data(); username, phone, pw = str(d.get("username", "")).strip(), str(d.get("phone", "")).strip(), str(d.get("password", ""))
    if not re.fullmatch(r"010\d{8}", phone) or len(username) < 2 or len(pw) < 8: return fail("입력 형식을 확인하세요")
    con = db()
    try:
        admin = 1 if con.execute("SELECT COUNT(*) FROM user").fetchone()[0] == 0 else 0
        cur = con.execute("INSERT INTO user(username,phone,password,is_admin) VALUES(?,?,?,?)", (username, phone, password_hash(pw), admin)); con.commit(); session["user_id"] = cur.lastrowid
    except sqlite3.IntegrityError: con.close(); return fail("아이디 또는 휴대폰이 이미 사용 중입니다", 409)
    con.close(); return reply("가입되었습니다", 201)

@app.get("/login")
def login_page(): return render_template("login.html", next=request.args.get("next", ""))

@app.post("/login")
def login():
    d = data(); ident = str(d.get("username") or d.get("phone") or ""); con = db(); u = con.execute("SELECT * FROM user WHERE username=? OR phone=?", (ident, ident)).fetchone(); con.close()
    if not u or not password_ok(str(d.get("password", "")), u["password"]): return fail("로그인 정보가 올바르지 않습니다", 401)
    session["user_id"] = u["id"]; nxt = str(d.get("next", ""));
    if nxt and nxt.startswith("/") and not nxt.startswith("//") and not wants_json(): return redirect(nxt)
    return reply("로그인되었습니다", 200)

@app.post("/logout")
@login_required
def logout(): session.clear(); return reply("로그아웃되었습니다")

@app.get("/posts")
def posts():
    u = current_user(); cond = "p.is_private=0" + (" OR p.author_id=?" if u else ""); args = (u["id"],) if u else ()
    return render_template("posts.html", posts=posts_query(cond, args, request.args.get("sort", "newest")), sort=request.args.get("sort", "newest"))

@app.post("/posts")
@login_required
def create_post():
    d = data(); title, content = str(d.get("title", "")).strip(), str(d.get("content", ""));
    if not title or not content: return fail("제목과 내용을 입력하세요")
    try: image = save_upload(request.files.get("image"))
    except ValueError as e: return fail(str(e))
    link = str(d.get("link_url", "")).strip() or None; pt, ps = preview(link) if link else ("", ""); con = db(); con.execute("INSERT INTO post(title,content,author_id,created_at,image_url,link_url,is_private,preview_title,preview_summary) VALUES(?,?,?,?,?,?,?,?,?)", (title,content,current_user()["id"],datetime.now(timezone.utc).isoformat(timespec="seconds"),image,link,1 if d.get("is_private") else 0,pt,ps)); con.commit(); con.close(); return reply("글이 등록되었습니다", 201)

@app.get("/posts/<int:pid>")
def post_detail(pid):
    con = db(); p = con.execute("SELECT p.*,u.username,u.signature FROM post p JOIN user u ON u.id=p.author_id WHERE p.id=?", (pid,)).fetchone(); cs = con.execute("SELECT c.*,u.username author FROM comment c JOIN user u ON u.id=c.author_id WHERE c.post_id=? ORDER BY c.id", (pid,)).fetchall(); con.close()
    if not p: return fail("글을 찾을 수 없습니다", 404)
    u=current_user()
    if p["is_private"] and (not u or (u["id"] != p["author_id"] and not u["is_admin"])): return fail("비공개 글입니다", 403)
    pd=dict(p); pd["author"]=pd.pop("username"); pd["content_html"]=safe_md(pd["content"]); pd["signature"]=(p["signature"] or "").replace("{{ username }}", p["username"])
    return render_template("post_detail.html", post=pd, comments=[dict(c) for c in cs])

@app.route("/posts/<int:pid>", methods=["PUT", "PATCH", "DELETE"])
@login_required
def edit_post(pid):
    con=db(); p=con.execute("SELECT * FROM post WHERE id=?",(pid,)).fetchone(); u=current_user()
    if not p: con.close(); return fail("글을 찾을 수 없습니다",404)
    if p["author_id"] != u["id"] and not u["is_admin"]: con.close(); return fail("권한이 없습니다",403)
    if request.method == "DELETE": con.execute("DELETE FROM post WHERE id=?",(pid,)); con.commit(); con.close(); return reply("삭제되었습니다")
    d=data(); con.execute("UPDATE post SET title=?,content=? WHERE id=?",(str(d.get("title",p["title"])).strip(),str(d.get("content",p["content"])),pid)); con.commit(); con.close(); return reply("수정되었습니다")

@app.post("/posts/<int:pid>/comments")
@login_required
def add_comment(pid):
    content=str(data().get("content","" )).strip(); con=db(); exists=con.execute("SELECT id FROM post WHERE id=?",(pid,)).fetchone()
    if not exists: con.close(); return fail("글을 찾을 수 없습니다",404)
    con.execute("INSERT INTO comment(post_id,author_id,content) VALUES(?,?,?)",(pid,current_user()["id"],content)); con.commit(); con.close(); return reply("댓글이 등록되었습니다",201,f"/posts/{pid}")

@app.route("/comments/<int:cid>", methods=["PUT","PATCH","DELETE"])
@login_required
def edit_comment(cid):
    con=db(); c=con.execute("SELECT * FROM comment WHERE id=?",(cid,)).fetchone(); u=current_user()
    if not c: con.close(); return fail("댓글을 찾을 수 없습니다",404)
    if c["author_id"] != u["id"] and not u["is_admin"]: con.close(); return fail("권한이 없습니다",403)
    if request.method=="DELETE": con.execute("DELETE FROM comment WHERE id=?",(cid,))
    else: con.execute("UPDATE comment SET content=? WHERE id=?",(str(data().get("content","")).strip(),cid))
    con.commit(); con.close(); return reply("처리되었습니다")

@app.get("/search")
def search():
    q=request.args.get("q","").strip(); u=current_user(); cond="(p.title LIKE ? OR p.content LIKE ?) AND (p.is_private=0" + (" OR p.author_id=?" if u else "") + ")"; args=[f"%{q}%",f"%{q}%"] + ([u["id"]] if u else [])
    return render_template("search.html",q=q,posts=posts_query(cond,args,request.args.get("sort","newest")),sort=request.args.get("sort","newest"))

@app.get("/users/<int:uid>")
def profile(uid):
    con=db(); u=con.execute("SELECT * FROM user WHERE id=?",(uid,)).fetchone(); con.close()
    if not u:return fail("사용자를 찾을 수 없습니다",404)
    ud=dict(u); me=current_user();
    if not me or me["id"] != uid: ud.pop("phone",None)
    return render_template("profile.html",user=ud,posts=posts_query("p.author_id=? AND (p.is_private=0 OR p.author_id=?)",(uid,uid)))

@app.get("/account/password")
@login_required
def password_page(): return render_template("account_password.html")

@app.post("/account/password")
@login_required
def change_password():
    d=data(); u=current_user()
    if not password_ok(str(d.get("old_password","")),u["password"]): return fail("현재 비밀번호가 올바르지 않습니다",400)
    if len(str(d.get("new_password","")))<8:return fail("새 비밀번호는 8자 이상이어야 합니다")
    con=db();con.execute("UPDATE user SET password=? WHERE id=?",(password_hash(str(d["new_password"])),u["id"]));con.commit();con.close();return reply("비밀번호가 변경되었습니다")

@app.get("/password/reset/request")
def reset_request_page(): return render_template("reset_request.html")

@app.post("/password/reset/request")
def reset_request():
    name=str(data().get("username","")); con=db();u=con.execute("SELECT id FROM user WHERE username=?",(name,)).fetchone();con.close()
    if u:
        token = RESET_SERIALIZER.dumps({"uid": u["id"]})
        print("RESET LINK:", url_for("reset_page",token=token,_external=True), flush=True)
    return reply("사용자가 있으면 재설정 링크를 출력했습니다")

@app.get("/password/reset")
def reset_page(): return render_template("reset.html",token=request.args.get("token",""))

@app.post("/password/reset")
def reset_password():
    d=data(); token=str(d.get("token",""))
    try:
        item = RESET_SERIALIZER.loads(token, max_age=900)
    except (BadSignature, SignatureExpired, TypeError):
        return fail("토큰이 만료되었거나 올바르지 않습니다",400)
    if len(str(d.get("new_password","")))<8:return fail("새 비밀번호는 8자 이상이어야 합니다")
    con=db();con.execute("UPDATE user SET password=? WHERE id=?",(password_hash(str(d["new_password"])),item["uid"]));con.commit();con.close();return reply("비밀번호가 재설정되었습니다")

@app.post("/verify/request")
@login_required
def verify_request():
    code=f"{secrets.randbelow(1000000):06d}"; session["verify_code"]={"code":code,"exp":datetime.now(timezone.utc).timestamp()+600}; print("VERIFY CODE:",code,flush=True); return reply("인증번호를 출력했습니다")

@app.post("/verify/confirm")
@login_required
def verify_confirm():
    d=data(); x=session.get("verify_code",{}); 
    if not x or x.get("exp",0)<datetime.now(timezone.utc).timestamp() or not secrets.compare_digest(str(d.get("code","")),x.get("code","")): return fail("인증번호가 올바르지 않습니다",400)
    con=db();con.execute("UPDATE user SET phone_verified=1 WHERE id=?",(current_user()["id"],));con.commit();con.close();session.pop("verify_code",None);return reply("휴대폰 인증이 완료되었습니다")

@app.post("/profile/signature")
@login_required
def signature():
    con=db();con.execute("UPDATE user SET signature=? WHERE id=?",(str(data().get("signature",""))[:300],current_user()["id"]));con.commit();con.close();return reply("서명이 저장되었습니다")

@app.post("/profile/avatar")
@login_required
def avatar():
    try: url=save_upload(request.files.get("image")) or str(data().get("avatar_url","" )).strip()
    except ValueError as e:return jsonify({"error":str(e)}),400
    if not url or urllib.parse.urlparse(url).scheme not in {"http","https",""}:return jsonify({"error":"올바른 이미지 주소가 필요합니다"}),400
    con=db();con.execute("UPDATE user SET avatar_url=? WHERE id=?",(url,current_user()["id"]));con.commit();con.close();return jsonify({"url":url,"image_url":url,"avatar_url":url}),200

@app.post("/points/gift")
@login_required
def gift():
    d=data(); amount=int(d.get("amount",0)); me=current_user(); con=db();to=con.execute("SELECT * FROM user WHERE username=?",(str(d.get("to","")),)).fetchone()
    if not to or amount<=0 or to["id"]==me["id"] or me["points"]<amount:con.close();return fail("포인트 선물을 처리할 수 없습니다",400)
    con.execute("UPDATE user SET points=points-? WHERE id=?",(amount,me["id"]));con.execute("UPDATE user SET points=points+? WHERE id=?",(amount,to["id"]));con.commit();con.close();return reply("포인트를 선물했습니다")

@app.get("/admin")
@admin_required
def admin():
    con=db();a=con.execute("SELECT COUNT(*) FROM user").fetchone()[0];b=con.execute("SELECT COUNT(*) FROM post").fetchone()[0];con.close();return render_template("admin.html",user_count=a,post_count=b)

@app.get("/admin/users")
@admin_required
def admin_users():
    con=db();users=con.execute("SELECT * FROM user ORDER BY id").fetchall();con.close();return render_template("admin_users.html",users=users)

@app.post("/admin/users/<int:uid>/role")
@admin_required
def role(uid):
    role=str(data().get("role","user"));
    if role not in {"admin","user"}:return fail("역할이 올바르지 않습니다")
    con=db();con.execute("UPDATE user SET is_admin=? WHERE id=?",(role=="admin",uid));con.commit();con.close();return reply("역할이 변경되었습니다",200,"/admin/users")

@app.delete("/admin/users/<int:uid>")
@admin_required
def delete_user(uid):
    if uid == current_user()["id"]:return fail("본인 계정은 삭제할 수 없습니다",400)
    con=db();con.execute("DELETE FROM user WHERE id=?",(uid,));con.commit();con.close();return reply("사용자가 삭제되었습니다")

@app.get("/admin/users.csv")
@admin_required
def users_csv():
    con=db();rows=con.execute("SELECT username,phone FROM user ORDER BY id").fetchall();con.close();out=io.StringIO();w=csv.writer(out);w.writerow(["username","phone"]);w.writerows((r["username"],r["phone"]) for r in rows);return app.response_class("\ufeff"+out.getvalue(),mimetype="text/csv",headers={"Content-Disposition":"attachment; filename=users.csv"})

@app.errorhandler(413)
def too_large(e): return fail("파일이 너무 큽니다",413)

if __name__ == "__main__":
    init_db()
    app.run()
