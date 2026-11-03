import csv
import hashlib
import html
import os
import re
import secrets
import sqlite3
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from functools import wraps
from io import StringIO

import markdown
from flask import Flask, jsonify, make_response, redirect, render_template, request, session, url_for
from werkzeug.utils import secure_filename

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "board.db")
UPLOAD_DIR = os.path.join(BASE, "static", "uploads")
app = Flask(__name__)
RESET_TOKENS = {}

def load_env():
    path = os.path.join(BASE, ".env")
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"\''))

load_env()
app.secret_key = os.environ.get("SECRET_KEY", "development-secret-key")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    RESET_TOKENS.clear()
    if os.path.exists(DB_PATH): os.remove(DB_PATH)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    c = db()
    c.executescript("""
    CREATE TABLE user (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, phone TEXT UNIQUE NOT NULL, password TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0, avatar_url TEXT, phone_verified INTEGER NOT NULL DEFAULT 0, points INTEGER NOT NULL DEFAULT 100, signature TEXT);
    CREATE TABLE post (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, content TEXT NOT NULL, author_id INTEGER NOT NULL, created_at TEXT NOT NULL, image_url TEXT, link_url TEXT, is_private INTEGER NOT NULL DEFAULT 0, preview_title TEXT, preview_summary TEXT, FOREIGN KEY(author_id) REFERENCES user(id) ON DELETE CASCADE);
    CREATE TABLE comment (id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL, author_id INTEGER NOT NULL, content TEXT NOT NULL, FOREIGN KEY(post_id) REFERENCES post(id) ON DELETE CASCADE, FOREIGN KEY(author_id) REFERENCES user(id) ON DELETE CASCADE);
    """)
    c.commit(); c.close()

def wants_json(): return request.is_json or request.path == "/profile/avatar" or request.headers.get("Accept", "").startswith("application/json")
def val(name, default=""):
    data = request.get_json(silent=True) if request.is_json else request.form
    return (data.get(name, default) if data else default)
def result(message, status=200, next_url=None, data=None):
    if wants_json():
        body = data or {"message": message}
        return jsonify(body), status
    return render_template("message.html", message=message, next_url=next_url or "/posts"), status
def fail(message, status=400):
    if wants_json(): return jsonify(error=message), status
    return render_template("error.html", status=status, message=message), status
def current_user():
    uid = session.get("user_id")
    if not uid: return None
    c = db(); u = c.execute("SELECT * FROM user WHERE id=?", (uid,)).fetchone(); c.close()
    return u
@app.context_processor
def common(): return {"current_user": current_user()}
def auth(admin=False):
    def deco(fn):
        @wraps(fn)
        def wrapped(*a, **kw):
            u = current_user()
            if not u: return fail("로그인이 필요합니다", 401)
            if admin and not u["is_admin"]: return fail("관리자만 이용할 수 있습니다", 403)
            return fn(*a, **kw)
        return wrapped
    return deco
def user_dict(u): return dict(u) if u else None
def post_rows(where="", args=(), sort="newest"):
    order = {"oldest":"p.created_at ASC", "title":"p.title COLLATE NOCASE ASC"}.get(sort, "p.created_at DESC")
    c=db(); rows=c.execute(f"SELECT p.*, u.username author FROM post p JOIN user u ON u.id=p.author_id {where} ORDER BY {order}", args).fetchall(); c.close()
    return [dict(r) for r in rows]
def visible_clause():
    u=current_user(); return ("AND (p.is_private=0 OR p.author_id=?)", (u["id"],)) if u else ("AND p.is_private=0", ())
def save_upload(f):
    if not f or not f.filename: return None
    name = secrets.token_hex(8) + "_" + secure_filename(f.filename)
    f.save(os.path.join(UPLOAD_DIR, name)); return "/static/uploads/" + name
def password_hash(p): return hashlib.sha256(p.encode()).hexdigest()
def safe_next(n): return n if n and n.startswith("/") and not n.startswith("//") else None
def preview(url):
    try:
        if urllib.parse.urlparse(url).scheme not in ("http", "https"): return (None, None)
        req=urllib.request.Request(url, headers={"User-Agent":"BoardPreview/1.0"})
        text=urllib.request.urlopen(req, timeout=3).read(200000).decode("utf-8", "ignore")
        title=re.search(r"<title[^>]*>(.*?)</title>", text, re.I|re.S)
        desc=re.search(r'<meta[^>]+(?:name|property)=["\'](?:description|og:description)["\'][^>]+content=["\'](.*?)["\']', text, re.I|re.S)
        return (html.unescape(re.sub(r"<.*?>", "", title.group(1))).strip() if title else url, html.unescape(desc.group(1)).strip() if desc else None)
    except Exception: return (None, None)

@app.get("/")
def home(): return redirect("/posts")
@app.get("/signup")
def signup(): return render_template("signup.html")
@app.post("/signup")
def signup_post():
    username, phone, password = val("username").strip(), val("phone").strip(), val("password")
    if not username or not re.fullmatch(r"010\d{8}", phone) or not password: return fail("입력값을 확인하세요")
    c=db()
    try:
        admin=1 if c.execute("SELECT COUNT(*) FROM user").fetchone()[0] == 0 else 0
        cur=c.execute("INSERT INTO user(username,phone,password,is_admin) VALUES(?,?,?,?)", (username,phone,password_hash(password),admin)); c.commit(); session["user_id"]=cur.lastrowid
    except sqlite3.IntegrityError: c.close(); return fail("이미 사용 중인 아이디 또는 전화번호입니다", 409)
    c.close(); return result("가입 및 로그인이 완료되었습니다", 201)
@app.get("/login")
def login(): return render_template("login.html", next=request.args.get("next", ""))
@app.post("/login")
def login_post():
    ident=val("username") or val("phone"); c=db(); u=c.execute("SELECT * FROM user WHERE username=? OR phone=?", (ident,ident)).fetchone(); c.close()
    if not u or u["password"] != password_hash(val("password")): return fail("로그인 정보가 올바르지 않습니다", 401)
    session["user_id"]=u["id"]; nxt=safe_next(val("next"))
    if nxt: return redirect(nxt, 302)
    return result("로그인되었습니다")
@app.post("/logout")
def logout(): session.clear(); return result("로그아웃되었습니다")
@app.get("/posts")
def posts():
    sort=request.args.get("sort", "newest"); clause,args=visible_clause(); return render_template("posts.html", posts=post_rows(clause,args,sort), sort=sort)
@app.post("/posts")
@auth()
def create_post():
    title, content, link=val("title").strip(), val("content"), val("link_url").strip(); image=save_upload(request.files.get("image")); pt,ps=preview(link) if link else (None,None); c=db(); c.execute("INSERT INTO post(title,content,author_id,created_at,image_url,link_url,is_private,preview_title,preview_summary) VALUES(?,?,?,?,?,?,?,?,?)", (title,content,current_user()["id"],datetime.now(timezone.utc).isoformat(),image,link,int(bool(val("is_private"))),pt,ps)); c.commit(); c.close(); return result("글이 작성되었습니다",201)
@app.get("/posts/<int:pid>")
def detail(pid):
    c=db(); p=c.execute("SELECT p.*,u.username author,u.signature FROM post p JOIN user u ON u.id=p.author_id WHERE p.id=?",(pid,)).fetchone();
    if not p: c.close(); return fail("글을 찾을 수 없습니다",404)
    u=current_user()
    if p["is_private"] and (not u or u["id"] != p["author_id"]): c.close(); return fail("비공개 글입니다",403)
    comments=c.execute("SELECT c.*,u.username author FROM comment c JOIN user u ON u.id=c.author_id WHERE c.post_id=? ORDER BY c.id",(pid,)).fetchall(); c.close(); d=dict(p); d["content_html"]=markdown.markdown(p["content"]); d["signature"]=(p["signature"] or "").replace("{{ username }}",p["author"]); return render_template("post_detail.html",post=d,comments=[dict(x) for x in comments])
@app.route("/posts/<int:pid>", methods=["PUT","PATCH","DELETE"])
@auth()
def edit_post(pid):
    c=db(); p=c.execute("SELECT * FROM post WHERE id=?",(pid,)).fetchone(); u=current_user()
    if not p: c.close(); return fail("글을 찾을 수 없습니다",404)
    if p["author_id"] != u["id"] and not u["is_admin"]: c.close(); return fail("권한이 없습니다",403)
    if request.method == "DELETE": c.execute("DELETE FROM post WHERE id=?",(pid,)); msg="글이 삭제되었습니다"
    else: c.execute("UPDATE post SET title=?,content=? WHERE id=?",(val("title"),val("content"),pid)); msg="글이 수정되었습니다"
    c.commit(); c.close(); return result(msg)
@app.post("/posts/<int:pid>/comments")
@auth()
def add_comment(pid):
    c=db(); c.execute("INSERT INTO comment(post_id,author_id,content) VALUES(?,?,?)",(pid,current_user()["id"],val("content"))); c.commit(); c.close(); return result("댓글이 등록되었습니다")
@app.route("/comments/<int:cid>", methods=["PUT","PATCH","DELETE"])
@auth()
def edit_comment(cid):
    c=db(); row=c.execute("SELECT * FROM comment WHERE id=?",(cid,)).fetchone(); u=current_user()
    if not row: c.close(); return fail("댓글을 찾을 수 없습니다",404)
    if row["author_id"] != u["id"] and not u["is_admin"]: c.close(); return fail("권한이 없습니다",403)
    if request.method == "DELETE": c.execute("DELETE FROM comment WHERE id=?",(cid,)); msg="댓글이 삭제되었습니다"
    else: c.execute("UPDATE comment SET content=? WHERE id=?",(val("content"),cid)); msg="댓글이 수정되었습니다"
    c.commit(); c.close(); return result(msg)
@app.get("/search")
def search():
    q=request.args.get("q",""); sort=request.args.get("sort","newest"); clause,args=visible_clause(); extra=" AND (p.title LIKE ? OR p.content LIKE ?)"; return render_template("search.html",q=q,posts=post_rows(clause+extra,args+(f"%{q}%",f"%{q}%"),sort),sort=sort)
@app.get("/users/<int:uid>")
def profile(uid):
    c=db(); u=c.execute("SELECT * FROM user WHERE id=?",(uid,)).fetchone(); c.close()
    if not u: return fail("사용자를 찾을 수 없습니다",404)
    rows=post_rows("AND p.author_id=? AND (p.is_private=0 OR p.author_id=?)",(uid,uid)); return render_template("profile.html",user=dict(u),posts=rows)
@app.get("/account/password")
@auth()
def password_page(): return render_template("account_password.html")
@app.post("/account/password")
@auth()
def password_change():
    u=current_user()
    if u["password"] != password_hash(val("old_password")): return fail("현재 비밀번호가 올바르지 않습니다",400)
    c=db(); c.execute("UPDATE user SET password=? WHERE id=?",(password_hash(val("new_password")),u["id"])); c.commit(); c.close(); return result("비밀번호가 변경되었습니다")
@app.get("/password/reset/request")
def reset_request(): return render_template("reset_request.html")
@app.post("/password/reset/request")
def reset_request_post():
    c=db(); u=c.execute("SELECT id FROM user WHERE username=?",(val("username"),)).fetchone(); c.close()
    if not u: return fail("사용자를 찾을 수 없습니다",404)
    token=secrets.token_urlsafe(32); RESET_TOKENS[token]=u["id"]; session["reset_"+token]=u["id"]; link=url_for("reset_page",token=token,_external=True); print("RESET LINK:",link,flush=True); return result("재설정 링크를 서버에 출력했습니다")
@app.get("/password/reset")
def reset_page(): return render_template("reset.html",token=request.args.get("token", ""))
@app.post("/password/reset")
def reset_post():
    token=val("token"); uid=RESET_TOKENS.pop(token,None)
    if uid is None: uid=session.pop("reset_"+token,None)
    if not uid: return fail("토큰이 올바르지 않습니다",400)
    c=db(); c.execute("UPDATE user SET password=? WHERE id=?",(password_hash(val("new_password")),uid)); c.commit(); c.close(); return result("비밀번호가 재설정되었습니다")
@app.post("/verify/request")
@auth()
def verify_request():
    code=f"{secrets.randbelow(1000000):06d}"; session["verify_code"]=code; print("VERIFY CODE:",code,flush=True); return result("인증번호를 서버에 출력했습니다")
@app.post("/verify/confirm")
@auth()
def verify_confirm():
    if val("code") != session.pop("verify_code",None): return fail("인증번호가 올바르지 않습니다",400)
    c=db(); c.execute("UPDATE user SET phone_verified=1 WHERE id=?",(current_user()["id"],)); c.commit(); c.close(); return result("휴대폰 인증이 완료되었습니다")
@app.post("/profile/signature")
@auth()
def signature():
    c=db(); c.execute("UPDATE user SET signature=? WHERE id=?",(val("signature"),current_user()["id"])); c.commit(); c.close(); return result("서명이 저장되었습니다")
@app.post("/profile/avatar")
@auth()
def avatar():
    url=save_upload(request.files.get("image")) or val("avatar_url").strip()
    if not url: return jsonify(error="이미지 또는 URL이 필요합니다"),400
    c=db(); c.execute("UPDATE user SET avatar_url=? WHERE id=?",(url,current_user()["id"])); c.commit(); c.close(); return jsonify(url=url,image_url=url,avatar_url=url),200
@app.post("/points/gift")
@auth()
def gift():
    try: amount=int(val("amount"))
    except ValueError: return fail("포인트 수량이 올바르지 않습니다")
    u=current_user(); c=db(); to=c.execute("SELECT * FROM user WHERE username=?",(val("to"),)).fetchone()
    if not to or to["id"]==u["id"] or amount<=0 or u["points"]<amount: c.close(); return fail("포인트를 보낼 수 없습니다",400)
    c.execute("UPDATE user SET points=points-? WHERE id=?",(amount,u["id"])); c.execute("UPDATE user SET points=points+? WHERE id=?",(amount,to["id"])); c.commit(); c.close(); return result("포인트를 보냈습니다")
@app.get("/admin")
@auth(True)
def admin():
    c=db(); uc=c.execute("SELECT COUNT(*) FROM user").fetchone()[0]; pc=c.execute("SELECT COUNT(*) FROM post").fetchone()[0]; c.close(); return render_template("admin.html",user_count=uc,post_count=pc)
@app.get("/admin/users")
@auth(True)
def admin_users():
    c=db(); users=[dict(x) for x in c.execute("SELECT * FROM user ORDER BY id")]; c.close(); return render_template("admin_users.html",users=users)
@app.post("/admin/users/<int:uid>/role")
@auth(True)
def role(uid):
    r=val("role");
    if r not in ("admin","user"): return fail("역할이 올바르지 않습니다")
    c=db(); c.execute("UPDATE user SET is_admin=? WHERE id=?",(r=="admin",uid)); c.commit(); c.close(); return result("역할이 변경되었습니다")
@app.delete("/admin/users/<int:uid>")
@auth(True)
def delete_user(uid):
    if uid == current_user()["id"]: return fail("자기 자신은 삭제할 수 없습니다",400)
    c=db(); c.execute("DELETE FROM user WHERE id=?",(uid,)); c.commit(); c.close(); return result("사용자가 삭제되었습니다")
@app.get("/admin/users.csv")
@auth(True)
def users_csv():
    c=db(); rows=c.execute("SELECT username,phone FROM user ORDER BY id").fetchall(); c.close(); s=StringIO(); w=csv.writer(s); w.writerow(["username","phone"]); w.writerows(rows); r=make_response(s.getvalue()); r.headers["Content-Type"]="text/csv; charset=utf-8"; r.headers["Content-Disposition"]="attachment; filename=users.csv"; return r

if __name__ == "__main__":
    init_db()
    app.run()
