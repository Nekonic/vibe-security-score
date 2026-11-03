import os,secrets,sqlite3,urllib.request,urllib.parse,html,re
from functools import wraps
from flask import Flask,request,session,jsonify,render_template,redirect,url_for,abort
from werkzeug.utils import secure_filename
BASE=os.path.dirname(os.path.abspath(__file__));DB=os.path.join(BASE,"board.db");UP=os.path.join(BASE,"static","uploads");os.makedirs(UP,exist_ok=True)
app=Flask(__name__);app.config["SECRET_KEY"]=os.environ.get("SECRET_KEY") or secrets.token_hex(32)
def db(): c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;return c
def init_db():
 if os.path.exists(DB):os.remove(DB)
 c=db();c.executescript("""CREATE TABLE user(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,phone TEXT NOT NULL,password TEXT NOT NULL,is_admin INTEGER NOT NULL DEFAULT 0,avatar_url TEXT);CREATE TABLE post(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,content TEXT NOT NULL,author_id INTEGER NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP,image_url TEXT,link_url TEXT,preview_title TEXT,preview_summary TEXT);CREATE TABLE comment(id INTEGER PRIMARY KEY AUTOINCREMENT,post_id INTEGER NOT NULL,author_id INTEGER NOT NULL,content TEXT NOT NULL);""");c.commit();c.close()
def current():
 uid=session.get("user_id")
 if not uid:return None
 c=db();u=c.execute("SELECT * FROM user WHERE id=?",(uid,)).fetchone();c.close();return u
def data():return request.get_json(silent=True) or request.form
def auth(f):
 @wraps(f)
 def w(*a,**k):
  if not current():return jsonify(error="login required"),401
  return f(*a,**k)
 return w
def admin(f):
 @wraps(f)
 def w(*a,**k):
  u=current()
  if not u or not u["is_admin"]:return jsonify(error="admin required"),403
  return f(*a,**k)
 return w
def upload(field):
 f=request.files.get(field)
 if not f or not f.filename:return None
 n=secrets.token_hex(8)+"_"+secure_filename(f.filename);f.save(os.path.join(UP,n));return "/static/uploads/"+n
def preview(link):
 if not link:return None,None
 try:
  if urllib.parse.urlparse(link).scheme not in ("http","https"):return None,None
  t=urllib.request.urlopen(link,timeout=3).read(300000).decode("utf8","ignore");m=re.search(r"<title[^>]*>(.*?)</title>",t,re.I|re.S);s=" ".join(html.unescape(re.sub("<[^>]+>"," ",t)).split());return (m.group(1).strip() if m else link),s[:240]
 except:return link,"미리보기를 가져오지 못했습니다."
@app.get("/")
def home():return redirect("/posts")
@app.post("/signup")
def signup():
 d=data();u=d.get("username","").strip();p=d.get("phone","").strip();pw=d.get("password","")
 if not u or not p or not pw or not re.fullmatch(r"010\d{8}",p):return jsonify(error="invalid fields"),400
 c=db()
 try:c.execute("INSERT INTO user(username,phone,password,is_admin) VALUES(?,?,?,?)",(u,p,pw,1 if c.execute("SELECT COUNT(*) n FROM user").fetchone()["n"]==0 else 0));c.commit()
 except sqlite3.IntegrityError:return jsonify(error="username exists"),409
 uid=c.execute("SELECT last_insert_rowid() x").fetchone()["x"];c.close();session["user_id"]=uid;return jsonify(username=u),201
@app.post("/login")
def login():
 d=data();i=d.get("username") or d.get("phone");c=db();u=c.execute("SELECT * FROM user WHERE (username=? OR phone=?) AND password=?",(i,i,d.get("password",""))).fetchone();c.close()
 if not u:return jsonify(error="invalid credentials"),401
 session["user_id"]=u["id"];return render_template("page.html",title="로그인",body=f"<h1>환영합니다, {html.escape(u['username'])}</h1><form method='post' action='/logout'><button>로그아웃</button></form>")
@app.post("/logout")
def logout():session.clear();return jsonify(message="logged out")
@app.post("/account/password")
@auth
def passwd():
 d=data();u=current()
 if u["password"]!=d.get("old_password"):return jsonify(error="wrong password"),403
 c=db();c.execute("UPDATE user SET password=? WHERE id=?",(d.get("new_password",""),u["id"]));c.commit();c.close();return jsonify(message="changed")
def getpost(i):
 c=db();p=c.execute("SELECT p.*,u.username FROM post p JOIN user u ON u.id=p.author_id WHERE p.id=?",(i,)).fetchone();cs=c.execute("SELECT c.*,u.username FROM comment c JOIN user u ON u.id=c.author_id WHERE post_id=?",(i,)).fetchall();c.close();return p,cs
@app.get("/posts")
def posts():
 s=request.args.get("sort");o={"oldest":"p.created_at ASC","title":"p.title COLLATE NOCASE ASC"}.get(s,"p.created_at DESC");c=db();ps=c.execute(f"SELECT p.*,u.username FROM post p JOIN user u ON u.id=p.author_id ORDER BY {o}").fetchall();c.close();return render_template("posts.html",posts=ps,query=None)
@app.post("/posts")
@auth
def create():
 d=data();t=d.get("title","").strip();x=d.get("content","");link=d.get("link_url");im=upload("image");pt,ps=preview(link)
 if not t or not x:return jsonify(error="required"),400
 c=db();c.execute("INSERT INTO post(title,content,author_id,image_url,link_url,preview_title,preview_summary) VALUES(?,?,?,?,?,?,?)",(t,x,current()["id"],im,link,pt,ps));c.commit();i=c.execute("SELECT last_insert_rowid() x").fetchone()["x"];c.close();return jsonify(id=i),201
@app.route("/posts/<int:i>",methods=["GET","PUT","PATCH","DELETE"])
def detail(i):
 p,cs=getpost(i)
 if not p:abort(404)
 if request.method=="GET":return render_template("detail.html",post=p,comments=cs,user=current())
 u=current()
 if not u or(u["id"]!=p["author_id"] and not u["is_admin"]):return jsonify(error="forbidden"),403
 c=db()
 if request.method=="DELETE":c.execute("DELETE FROM post WHERE id=?",(i,));c.execute("DELETE FROM comment WHERE post_id=?",(i,))
 else:d=data();c.execute("UPDATE post SET title=?,content=? WHERE id=?",(d.get("title",p["title"]),d.get("content",p["content"]),i))
 c.commit();c.close();return jsonify(message="ok")
@app.post("/posts/<int:i>/comments")
@auth
def comment(i):
 d=data();c=db();c.execute("INSERT INTO comment(post_id,author_id,content) VALUES(?,?,?)",(i,current()["id"],d.get("content","")));c.commit();c.close();return jsonify(message="ok"),201
@app.route("/comments/<int:i>",methods=["PUT","PATCH","DELETE"])
@auth
def editcomment(i):
 c=db();x=c.execute("SELECT * FROM comment WHERE id=?",(i,)).fetchone();u=current()
 if not x:abort(404)
 if x["author_id"]!=u["id"] and not u["is_admin"]:return jsonify(error="forbidden"),403
 if request.method=="DELETE":c.execute("DELETE FROM comment WHERE id=?",(i,))
 else:c.execute("UPDATE comment SET content=? WHERE id=?",(data().get("content",""),i))
 c.commit();c.close();return jsonify(message="ok")
@app.get("/search")
def search():
 q=request.args.get("q","");c=db();ps=c.execute("SELECT p.*,u.username FROM post p JOIN user u ON u.id=p.author_id WHERE p.title LIKE ? OR p.content LIKE ? ORDER BY p.created_at DESC",(f"%{q}%",f"%{q}%")).fetchall();c.close();return render_template("posts.html",posts=ps,query=q)
@app.get("/users/<int:i>")
def profile(i):
 c=db();u=c.execute("SELECT * FROM user WHERE id=?",(i,)).fetchone();ps=c.execute("SELECT * FROM post WHERE author_id=?",(i,)).fetchall();c.close()
 if not u:abort(404)
 return render_template("profile.html",profile=u,posts=ps,own=current() and current()["id"]==i)
@app.post("/profile/avatar")
@auth
def avatar():
 x=upload("image") or data().get("avatar_url");c=db();c.execute("UPDATE user SET avatar_url=? WHERE id=?",(x,current()["id"]));c.commit();c.close();return jsonify(url=x,image_url=x,avatar_url=x)
@app.get("/admin")
@admin
def ahome():return redirect("/admin/users")
@app.get("/admin/users")
@admin
def users():
 c=db();u=c.execute("SELECT * FROM user").fetchall();c.close();return render_template("users.html",users=u)
@app.post("/admin/users/<int:i>/role")
@admin
def role(i):
 d=data();c=db();c.execute("UPDATE user SET is_admin=? WHERE id=?",(d.get("role")=="admin",i));c.commit();c.close();return jsonify(message="ok")
@app.delete("/admin/users/<int:i>")
@admin
def deluser(i):
 c=db();c.execute("DELETE FROM user WHERE id=?",(i,));c.commit();c.close();return jsonify(message="ok")
if __name__ == "__main__":
 init_db()
 app.run()

