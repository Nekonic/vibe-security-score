import csv, hashlib, io, json, logging, os, re, secrets, sqlite3, time
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import bleach
import markdown
from flask import Flask, g, jsonify, make_response, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE = Path(__file__).resolve().parent
DB = BASE / "board.sqlite3"
UPLOADS = BASE / "static" / "uploads"
env_file = BASE / ".env"
if env_file.exists():
    for line in env_file.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1); os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
app = Flask(__name__)
app.config.update(SECRET_KEY=os.getenv("SECRET_KEY") or secrets.token_hex(32), SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_HTTPONLY=True, PERMANENT_SESSION_LIFETIME=timedelta(minutes=30))
logging.basicConfig(level=logging.INFO)
FAILS, VERIFY, RESET_TOKENS = {}, {}, {}
IMG_MAGIC = [(b"\xff\xd8\xff", "jpg"), (b"\x89PNG\r\n\x1a\n", "png"), (b"GIF87a", "gif"), (b"GIF89a", "gif"), (b"RIFF", "webp")]

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB); g.db.row_factory = sqlite3.Row; g.db.execute("PRAGMA foreign_keys=ON")
    return g.db
@app.teardown_appcontext
def close_db(e=None):
    c = g.pop("db", None)
    if c: c.close()
def init_db():
    if DB.exists(): DB.unlink()
    UPLOADS.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB)
    c.executescript('''CREATE TABLE user(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, phone TEXT UNIQUE NOT NULL, password TEXT NOT NULL, is_admin INTEGER DEFAULT 0, avatar_url TEXT, phone_verified INTEGER DEFAULT 0, session_ver INTEGER DEFAULT 0);
    CREATE TABLE post(id INTEGER PRIMARY KEY, title TEXT NOT NULL, content TEXT NOT NULL, author_id INTEGER NOT NULL, created_at TEXT NOT NULL, image_url TEXT, link_url TEXT, is_private INTEGER DEFAULT 0, preview_title TEXT, preview_summary TEXT, FOREIGN KEY(author_id) REFERENCES user(id) ON DELETE CASCADE);
    CREATE TABLE comment(id INTEGER PRIMARY KEY, post_id INTEGER NOT NULL, author_id INTEGER NOT NULL, content TEXT NOT NULL, FOREIGN KEY(post_id) REFERENCES post(id) ON DELETE CASCADE, FOREIGN KEY(author_id) REFERENCES user(id) ON DELETE CASCADE);'''); c.commit(); c.close()
def is_json(): return request.is_json or request.headers.get("Accept", "").find("application/json") >= 0
def data(): return request.get_json(silent=True) or request.form
def out(message, status=200, next_url="/posts"):
    return (jsonify(message=message), status) if is_json() else (render_template("message.html", message=message, next_url=next_url), status)
def err(message, status=400):
    return (jsonify(error=message), status) if is_json() else (render_template("error.html", status=status, message=message), status)
def valid_url(v): return bool(v) and urlparse(v).scheme in ("http", "https")
def password_ok(p, u): return len(p) >= 8 and re.search(r"[A-Za-z]", p) and re.search(r"\d", p) and re.search(r"[^A-Za-z0-9]", p) and p != u
def current():
    uid = session.get("uid")
    if not uid: return None
    u = db().execute("SELECT * FROM user WHERE id=?", (uid,)).fetchone()
    if not u or u["session_ver"] != session.get("session_ver"): session.clear(); return None
    return u
@app.before_request
def security():
    g.user = current(); g.csrf = session.setdefault("csrf", secrets.token_urlsafe(24))
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("Origin")
        if origin and origin.rstrip("/") != request.host_url.rstrip("/"): return err("잘못된 Origin입니다", 403)
        token = request.headers.get("X-CSRFToken") or request.form.get("csrf_token") or (request.get_json(silent=True) or {}).get("csrf_token")
        if token != g.csrf: return err("CSRF 토큰이 없습니다", 403)
@app.context_processor
def ctx(): return {"current_user": g.get("user"), "csrf_token": lambda: g.get("csrf")}
@app.after_request
def headers(r):
    r.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' https: data:; style-src 'self'; script-src 'self'"
    r.headers["X-Content-Type-Options"] = "nosniff"; r.headers["X-Frame-Options"] = "DENY"; r.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"; return r
def login_required(f):
    @wraps(f)
    def w(*a, **kw): return f(*a, **kw) if g.user else err("로그인이 필요합니다", 401)
    return w
def admin_required(f):
    @wraps(f)
    def w(*a, **kw): return f(*a, **kw) if g.user and g.user["is_admin"] else err("관리자만 이용할 수 있습니다", 403)
    return w
def rows(sql, args=()): return [dict(x) for x in db().execute(sql, args).fetchall()]
def sort_sql(s): return {"oldest":"created_at ASC", "title":"title COLLATE NOCASE ASC", "newest":"created_at DESC"}.get(s, "created_at DESC")
def post_rows(where="", args=(), sort="newest"):
    return rows(f"SELECT p.*, u.username author FROM post p JOIN user u ON u.id=p.author_id {where} ORDER BY {sort_sql(sort)}", args)
def safe_md(s): return bleach.clean(markdown.markdown(s, extensions=["extra"]), tags=["p","br","strong","em","ul","ol","li","a","blockquote","code","pre","h1","h2","h3"], attributes={"a":["href","title"]}, protocols=["http","https"])
def upload(file):
    raw = file.read(20); file.stream.seek(0); ext = next((e for m,e in IMG_MAGIC if raw.startswith(m)), None)
    if not ext: return None
    name = secrets.token_hex(16) + "." + ext; file.save(UPLOADS / name); return "/static/uploads/" + name

@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method == "GET": return render_template("signup.html")
    d=data(); u=d.get("username","").strip(); p=d.get("phone","").strip(); pw=d.get("password","")
    if not re.fullmatch(r"010\d{8}", p) or not password_ok(pw,u): return err("가입 정보가 올바르지 않습니다")
    try:
        c=db(); first=c.execute("SELECT count(*) FROM user").fetchone()[0] == 0; c.execute("INSERT INTO user(username,phone,password,is_admin) VALUES(?,?,?,?)",(u,p,generate_password_hash(pw),int(first))); c.commit(); uid=c.execute("SELECT last_insert_rowid()").fetchone()[0]; session.clear(); session.update(uid=uid,session_ver=0); session.permanent=True; return out("가입되었습니다",201)
    except sqlite3.IntegrityError: return err("이미 사용 중인 아이디 또는 전화번호입니다",409)
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "GET": return render_template("login.html", next=request.args.get("next", ""))
    d=data(); ident=(d.get("username") or d.get("phone") or "").strip(); key=ident; now=time.time(); f=FAILS.get(key)
    if f and f["n"] >= 5 and now < f["until"]: return err("잠시 후 다시 시도하세요",429)
    u=db().execute("SELECT * FROM user WHERE username=? OR phone=?",(ident,ident)).fetchone()
    if not u or not check_password_hash(u["password"],d.get("password", "")):
        x=FAILS.setdefault(key,{"n":0,"until":0}); x["n"]+=1; x["until"]=now+300 if x["n"]>=5 else 0; return err("로그인 정보가 올바르지 않습니다",401)
    FAILS.pop(key,None); session.clear(); session.update(uid=u["id"],session_ver=u["session_ver"]); session.permanent=True
    nxt=d.get("next"); return redirect(nxt if nxt and nxt.startswith("/") else "/posts",302) if nxt else out(f"{u['username']}님, 로그인되었습니다")
@app.post("/logout")
@login_required
def logout(): db().execute("UPDATE user SET session_ver=session_ver+1 WHERE id=?",(g.user["id"],)); db().commit(); session.clear(); return out("로그아웃되었습니다")
@app.get("/posts")
def posts():
    s=request.args.get("sort","newest"); return render_template("posts.html",posts=post_rows("WHERE p.is_private=0",sort=s),sort=s)
@app.post("/posts")
@login_required
def create_post():
    d=data(); title=d.get("title","").strip(); content=d.get("content","").strip()
    if not title or not content: return err("제목과 내용을 입력하세요")
    link=d.get("link_url","").strip(); image=upload(request.files["image"]) if request.files.get("image") and request.files["image"].filename else None
    pt=ps=None
    if link and valid_url(link):
        try:
            with urlopen(Request(link,headers={"User-Agent":"board"}),timeout=3) as r: text=r.read(200000).decode("utf-8","ignore"); pt=(re.search(r"<title[^>]*>(.*?)</title>",text,re.I|re.S) or [link])[1].strip(); ps=re.sub(r"<[^>]+>"," ",text)[:240]
        except Exception: pt=link
    c=db(); c.execute("INSERT INTO post(title,content,author_id,created_at,image_url,link_url,is_private,preview_title,preview_summary) VALUES(?,?,?,?,?,?,?,?,?)",(title,content,g.user["id"],datetime.now(timezone.utc).isoformat(),image,link if valid_url(link) else None,int(bool(d.get("is_private"))),pt,ps)); c.commit(); pid=c.execute("SELECT last_insert_rowid()").fetchone()[0]
    if is_json(): return jsonify(message="글이 작성되었습니다", id=pid, post_id=pid), 201
    return out("글이 작성되었습니다",201)
@app.get("/posts/<int:pid>")
def detail(pid):
    p=db().execute("SELECT p.*,u.username author FROM post p JOIN user u ON u.id=p.author_id WHERE p.id=?",(pid,)).fetchone()
    if not p: return err("글을 찾을 수 없습니다",404)
    if p["is_private"] and (not g.user or g.user["id"] != p["author_id"]): return err("비공개 글입니다",403)
    x=dict(p); x["content_html"]=safe_md(x["content"]); cs=rows("SELECT c.*,u.username author FROM comment c JOIN user u ON u.id=c.author_id WHERE post_id=? ORDER BY c.id",(pid,)); return render_template("post_detail.html",post=x,comments=cs)
def json_body(): return request.get_json(silent=True) or request.form
@app.route("/posts/<int:pid>", methods=["PUT","PATCH","DELETE"])
@login_required
def edit_post(pid):
    p=db().execute("SELECT * FROM post WHERE id=?",(pid,)).fetchone()
    if not p: return err("글을 찾을 수 없습니다",404)
    if request.method != "DELETE" and p["author_id"] != g.user["id"] and not g.user["is_admin"]: return err("권한이 없습니다",403)
    if request.method == "DELETE": db().execute("DELETE FROM post WHERE id=?",(pid,)); db().commit(); return jsonify(message="삭제되었습니다")
    d=json_body(); db().execute("UPDATE post SET title=?,content=? WHERE id=?",(d.get("title",p["title"]),d.get("content",p["content"]),pid)); db().commit(); return jsonify(message="수정되었습니다")
@app.post("/posts/<int:pid>/comments")
@login_required
def comment(pid):
    d=data(); db().execute("INSERT INTO comment(post_id,author_id,content) VALUES(?,?,?)",(pid,g.user["id"],d.get("content",""))); db().commit(); return out("댓글이 등록되었습니다")
@app.route("/comments/<int:cid>", methods=["PUT","PATCH","DELETE"])
@login_required
def edit_comment(cid):
    c=db().execute("SELECT * FROM comment WHERE id=?",(cid,)).fetchone()
    if not c: return err("댓글을 찾을 수 없습니다",404)
    if c["author_id"] != g.user["id"] and not g.user["is_admin"]: return err("권한이 없습니다",403)
    if request.method == "DELETE": db().execute("DELETE FROM comment WHERE id=?",(cid,))
    else: db().execute("UPDATE comment SET content=? WHERE id=?",(json_body().get("content",""),cid))
    db().commit(); return jsonify(message="처리되었습니다")
@app.get("/search")
def search():
    q=request.args.get("q",""); s=request.args.get("sort","newest"); return render_template("search.html",q=q,sort=s,posts=post_rows("WHERE p.title LIKE ? OR p.content LIKE ?",(f"%{q}%",f"%{q}%"),s))
@app.get("/users/<int:uid>")
def profile(uid):
    u=db().execute("SELECT * FROM user WHERE id=?",(uid,)).fetchone()
    if not u: return err("사용자를 찾을 수 없습니다",404)
    x=dict(u); x["phone"] = x["phone"] if g.user and g.user["id"]==uid else None; return render_template("profile.html",user=x,posts=post_rows("WHERE p.author_id=?",(uid,)))
@app.post("/profile/avatar")
@login_required
def avatar():
    v=None
    if request.files.get("image") and request.files["image"].filename: v=upload(request.files["image"])
    elif data().get("avatar_url") and valid_url(data().get("avatar_url")): v=data().get("avatar_url")
    if not v: return jsonify(error="이미지가 올바르지 않습니다"),400
    db().execute("UPDATE user SET avatar_url=? WHERE id=?",(v,g.user["id"])); db().commit(); return jsonify(url=v,image_url=v,avatar_url=v)
@app.route("/account/password", methods=["GET","POST"])
@login_required
def account_password():
    if request.method == "GET": return render_template("account_password.html")
    d=data(); u=g.user
    if not check_password_hash(u["password"],d.get("old_password","")) or not password_ok(d.get("new_password",""),u["username"]): return err("비밀번호가 올바르지 않습니다")
    db().execute("UPDATE user SET password=?,session_ver=session_ver+1 WHERE id=?",(generate_password_hash(d["new_password"]),u["id"])); db().commit(); session.clear(); return out("비밀번호가 변경되었습니다")
@app.get("/password/reset/request")
def reset_request(): return render_template("reset_request.html")
@app.post("/password/reset/request")
def reset_request_post():
    u=db().execute("SELECT * FROM user WHERE username=?",(data().get("username",""),)).fetchone()
    if u:
        t=secrets.token_urlsafe(32); RESET_TOKENS[t]=[u["id"],time.time()+900]; print("RESET LINK:",request.host_url.rstrip("/")+url_for("reset",token=t),flush=True)
    return out("재설정 링크를 확인하세요")
@app.get("/password/reset")
def reset(): return render_template("reset.html",token=request.args.get("token",""))
@app.post("/password/reset")
def reset_post():
    d=data(); token=d.get("token",""); item=RESET_TOKENS.get(token); u=db().execute("SELECT * FROM user WHERE id=?",(item[0],)).fetchone() if item and item[1]>time.time() else None
    if not u or not password_ok(d.get("new_password",""),u["username"]): return err("토큰 또는 비밀번호가 올바르지 않습니다")
    db().execute("UPDATE user SET password=?,session_ver=session_ver+1 WHERE id=?",(generate_password_hash(d["new_password"]),u["id"])); db().commit(); RESET_TOKENS.pop(token,None); return out("비밀번호가 재설정되었습니다")
@app.post("/verify/request")
@login_required
def verify_request():
    code=f"{secrets.randbelow(1000000):06d}"; VERIFY[g.user["id"]]={"code":code,"n":0,"expires":time.time()+300}; print("VERIFY CODE:",code,flush=True); return out("인증번호를 보냈습니다")
@app.post("/verify/confirm")
@login_required
def verify_confirm():
    v=VERIFY.get(g.user["id"]); code=data().get("code","")
    if not v or v["expires"]<time.time() or v["n"]>=5 or code != v["code"]:
        if v: v["n"]+=1
        if v and v["n"]>=5: VERIFY.pop(g.user["id"],None)
        return err("인증번호가 올바르지 않습니다")
    db().execute("UPDATE user SET phone_verified=1 WHERE id=?",(g.user["id"],)); db().commit(); VERIFY.pop(g.user["id"],None); return out("휴대폰 인증이 완료되었습니다")
@app.get("/admin")
@admin_required
def admin(): return render_template("admin.html",user_count=db().execute("SELECT count(*) FROM user").fetchone()[0],post_count=db().execute("SELECT count(*) FROM post").fetchone()[0])
@app.get("/admin/users")
@admin_required
def admin_users(): return render_template("admin_users.html",users=rows("SELECT * FROM user ORDER BY id"))
@app.post("/admin/users/<int:uid>/role")
@admin_required
def role(uid):
    r=data().get("role");
    if r not in ("admin","user"): return err("역할이 올바르지 않습니다")
    db().execute("UPDATE user SET is_admin=? WHERE id=?",(r=="admin",uid)); db().commit(); return out("역할이 변경되었습니다",200,"/admin/users")
@app.delete("/admin/users/<int:uid>")
@admin_required
def delete_user(uid):
    if uid==g.user["id"]: return err("자기 자신은 삭제할 수 없습니다")
    db().execute("DELETE FROM user WHERE id=?",(uid,)); db().commit(); return jsonify(message="삭제되었습니다")
@app.get("/admin/users.csv")
@admin_required
def users_csv():
    s=io.StringIO(); w=csv.writer(s); w.writerow(["username","phone"]); w.writerows(db().execute("SELECT username,phone FROM user ORDER BY id")); r=make_response(s.getvalue()); r.headers["Content-Type"]="text/csv; charset=utf-8"; r.headers["Content-Disposition"]="attachment; filename=users.csv"; return r

if __name__ == "__main__":
    init_db()
    app.run()
