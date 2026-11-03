import os, re, secrets, sqlite3, html
from functools import wraps
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import urlparse
from flask import Flask, request, session, redirect, url_for, jsonify, render_template, send_from_directory

BASE = Path(__file__).resolve().parent
DB = BASE / "board.sqlite3"
UPLOADS = BASE / "static" / "uploads"
UPLOADS.mkdir(parents=True, exist_ok=True)
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def init_db():
    if DB.exists(): DB.unlink()
    c = db()
    c.executescript('''
    CREATE TABLE user (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, phone TEXT NOT NULL, password TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0, avatar_url TEXT);
    CREATE TABLE post (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, content TEXT NOT NULL, author_id INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, image_url TEXT, link_url TEXT, preview_title TEXT, preview_summary TEXT, FOREIGN KEY(author_id) REFERENCES user(id) ON DELETE CASCADE);
    CREATE TABLE comment (id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL, author_id INTEGER NOT NULL, content TEXT NOT NULL, FOREIGN KEY(post_id) REFERENCES post(id) ON DELETE CASCADE, FOREIGN KEY(author_id) REFERENCES user(id) ON DELETE CASCADE);
    INSERT INTO user(username,phone,password,is_admin) VALUES ('admin','01000000000','admin',1);
    '''); c.commit(); c.close()

def payload(): return request.form if request.form else (request.get_json(silent=True) or {})
def current_user():
    uid = session.get('user_id')
    if not uid: return None
    c=db(); u=c.execute('SELECT * FROM user WHERE id=?',(uid,)).fetchone(); c.close(); return u
def require_login(f):
    @wraps(f)
    def w(*a,**kw):
        if not current_user(): return jsonify(error='login required'), 401
        return f(*a,**kw)
    return w
def admin_required(f):
    @wraps(f)
    def w(*a,**kw):
        u=current_user()
        if not u or not u['is_admin']: return jsonify(error='admin required'), 403
        return f(*a,**kw)
    return w
def upload(field='image'):
    f=request.files.get(field)
    if not f or not f.filename: return None
    ext=Path(f.filename).suffix.lower()[:10]
    name=secrets.token_hex(16)+ext; f.save(UPLOADS/name); return '/static/uploads/'+name
def ok(data, code=200):
    return jsonify(data), code if request.is_json else code

@app.route('/static/uploads/<path:name>')
def uploaded(name): return send_from_directory(UPLOADS, name)

@app.route('/')
def home(): return redirect(url_for('posts'))

@app.post('/signup')
def signup():
    p=payload(); username=str(p.get('username','')).strip(); phone=str(p.get('phone','')).strip(); password=str(p.get('password',''))
    if not username or not password or not re.fullmatch(r'010\d{8}',phone): return jsonify(error='invalid fields'),400
    try:
        c=db(); cur=c.execute('INSERT INTO user(username,phone,password,is_admin,avatar_url) VALUES(?,?,?,?,?)',(username,phone,password,0,None)); c.commit(); uid=cur.lastrowid; c.close()
    except sqlite3.IntegrityError: return jsonify(error='username already exists'),409
    session['user_id']=uid; return jsonify(message='signed up', username=username),201

@app.post('/login')
def login():
    p=payload(); ident=str(p.get('username') or p.get('phone') or ''); c=db(); u=c.execute('SELECT * FROM user WHERE (username=? OR phone=?) AND password=?',(ident,ident,str(p.get('password','')))).fetchone(); c.close()
    if not u: return jsonify(error='invalid credentials'),401
    session['user_id']=u['id']; return jsonify(message='logged in', username=u['username'], logout='/logout'),200

@app.post('/logout')
def logout(): session.clear(); return jsonify(message='logged out')

@app.post('/account/password')
@require_login
def password_change():
    p=payload(); u=current_user()
    if p.get('old_password') != u['password'] or not p.get('new_password'): return jsonify(error='invalid password'),400
    c=db(); c.execute('UPDATE user SET password=? WHERE id=?',(p['new_password'],u['id'])); c.commit(); c.close(); return jsonify(message='password changed')

def post_data(row):
    d=dict(row); d['content_html']=html.escape(d['content']).replace('\n','<br>'); return d

@app.get('/posts')
def posts():
    sort=request.args.get('sort','newest'); order={'oldest':'created_at ASC','title':'title COLLATE NOCASE ASC'}.get(sort,'created_at DESC'); c=db(); rows=[post_data(x) for x in c.execute(f'SELECT p.*,u.username FROM post p JOIN user u ON u.id=p.author_id ORDER BY {order}')]; c.close(); return render_template('posts.html',posts=rows,user=current_user(),sort=sort)

@app.post('/posts')
@require_login
def create_post():
    p=payload(); title=str(p.get('title','')).strip(); content=str(p.get('content','')).strip();
    if not title or not content: return jsonify(error='title and content required'),400
    image=upload(); link=str(p.get('link_url','')).strip() or None; pt=ps=None
    if link:
        try:
            raw=urlopen(Request(link,headers={'User-Agent':'Mozilla/5.0'}),timeout=3).read(100000).decode('utf-8','ignore'); m=re.search(r'<title[^>]*>(.*?)</title>',raw,re.I|re.S); pt=re.sub(r'\s+',' ',html.unescape(m.group(1))).strip() if m else link; ps=re.sub(r'<[^>]+>',' ',raw); ps=re.sub(r'\s+',' ',ps).strip()[:240]
        except Exception: pt=link; ps='미리보기를 가져오지 못했습니다.'
    c=db(); cur=c.execute('INSERT INTO post(title,content,author_id,image_url,link_url,preview_title,preview_summary) VALUES(?,?,?,?,?,?,?)',(title,content,current_user()['id'],image,link,pt,ps)); c.commit(); pid=cur.lastrowid; c.close(); return jsonify(id=pid,message='created',image_url=image),201

@app.get('/posts/<int:pid>')
def detail(pid):
    c=db(); p=c.execute('SELECT p.*,u.username FROM post p JOIN user u ON u.id=p.author_id WHERE p.id=?',(pid,)).fetchone(); comments=[dict(x) for x in c.execute('SELECT c.*,u.username FROM comment c JOIN user u ON u.id=c.author_id WHERE post_id=? ORDER BY c.id',(pid,))]; c.close()
    if not p: return jsonify(error='not found'),404
    return render_template('detail.html',post=post_data(p),comments=comments,user=current_user())

def owns(author):
    u=current_user(); return u and (u['id']==author or u['is_admin'])
@app.route('/posts/<int:pid>',methods=['PUT','PATCH','DELETE'])
@require_login
def edit_post(pid):
    c=db(); p=c.execute('SELECT * FROM post WHERE id=?',(pid,)).fetchone()
    if not p: c.close(); return jsonify(error='not found'),404
    if not owns(p['author_id']): c.close(); return jsonify(error='forbidden'),403
    if request.method=='DELETE': c.execute('DELETE FROM post WHERE id=?',(pid,)); c.commit(); c.close(); return jsonify(message='deleted')
    x=payload(); c.execute('UPDATE post SET title=?,content=? WHERE id=?',(x.get('title',p['title']),x.get('content',p['content']),pid)); c.commit(); c.close(); return jsonify(message='updated')

@app.post('/posts/<int:pid>/comments')
@require_login
def add_comment(pid):
    p=payload(); content=str(p.get('content','')).strip(); c=db()
    if not c.execute('SELECT id FROM post WHERE id=?',(pid,)).fetchone(): c.close(); return jsonify(error='not found'),404
    if not content: c.close(); return jsonify(error='content required'),400
    cur=c.execute('INSERT INTO comment(post_id,author_id,content) VALUES(?,?,?)',(pid,current_user()['id'],content)); c.commit(); cid=cur.lastrowid; c.close(); return jsonify(id=cid,message='commented'),201

@app.route('/comments/<int:cid>',methods=['PUT','PATCH','DELETE'])
@require_login
def edit_comment(cid):
    c=db(); x=c.execute('SELECT * FROM comment WHERE id=?',(cid,)).fetchone()
    if not x: c.close(); return jsonify(error='not found'),404
    if not owns(x['author_id']): c.close(); return jsonify(error='forbidden'),403
    if request.method=='DELETE': c.execute('DELETE FROM comment WHERE id=?',(cid,))
    else: c.execute('UPDATE comment SET content=? WHERE id=?',(payload().get('content',''),cid))
    c.commit(); c.close(); return jsonify(message='done')

@app.get('/search')
def search():
    q=request.args.get('q',''); sort=request.args.get('sort','newest'); order='title ASC' if sort=='title' else ('created_at ASC' if sort=='oldest' else 'created_at DESC'); c=db(); rows=[post_data(x) for x in c.execute(f"SELECT p.*,u.username FROM post p JOIN user u ON u.id=p.author_id WHERE p.title LIKE ? OR p.content LIKE ? ORDER BY {order}",(f'%{q}%',f'%{q}%'))]; c.close(); return render_template('posts.html',posts=rows,user=current_user(),sort=sort,q=q)

@app.get('/users/<int:uid>')
def profile(uid):
    c=db(); u=c.execute('SELECT * FROM user WHERE id=?',(uid,)).fetchone(); ps=[post_data(x) for x in c.execute('SELECT p.*,u.username FROM post p JOIN user u ON u.id=p.author_id WHERE author_id=? ORDER BY p.id DESC',(uid,))]; c.close()
    if not u: return jsonify(error='not found'),404
    return render_template('profile.html',profile=u,posts=ps,user=current_user(),show_phone=current_user() and current_user()['id']==uid)

@app.post('/profile/avatar')
@require_login
def avatar():
    p=payload(); image=upload() or str(p.get('avatar_url','')).strip()
    if not image: return jsonify(error='image or avatar_url required'),400
    c=db(); c.execute('UPDATE user SET avatar_url=? WHERE id=?',(image,current_user()['id'])); c.commit(); c.close(); return jsonify(url=image,image_url=image,avatar_url=image)

@app.get('/admin')
@admin_required
def admin(): return render_template('admin.html',user=current_user())
@app.get('/admin/users')
@admin_required
def admin_users():
    c=db(); users=[dict(x) for x in c.execute('SELECT id,username,phone,is_admin,avatar_url FROM user ORDER BY id')]; c.close(); return jsonify(users=users)
@app.post('/admin/users/<int:uid>/role')
@admin_required
def role(uid):
    r=payload().get('role');
    if r not in ('admin','user'): return jsonify(error='invalid role'),400
    c=db(); c.execute('UPDATE user SET is_admin=? WHERE id=?',(r=='admin',uid)); c.commit(); c.close(); return jsonify(message='role updated')
@app.delete('/admin/users/<int:uid>')
@admin_required
def delete_user(uid):
    if uid==1: return jsonify(error='cannot delete initial admin'),400
    c=db(); c.execute('DELETE FROM user WHERE id=?',(uid,)); c.commit(); c.close(); return jsonify(message='deleted')

if __name__ == "__main__":
    init_db()
    app.run()
