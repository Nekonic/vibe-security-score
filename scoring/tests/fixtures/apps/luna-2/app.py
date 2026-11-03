import os, secrets, sqlite3, uuid, urllib.request
from functools import wraps
from urllib.parse import urlparse
from flask import Flask, request, session, redirect, url_for, jsonify, render_template, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
DB = os.path.join(app.root_path, 'board.sqlite3')

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c
def init_db():
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    if os.path.exists(DB): os.remove(DB)
    c = db()
    c.executescript('''CREATE TABLE user(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, phone TEXT NOT NULL, password TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0, avatar_url TEXT);
    CREATE TABLE post(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, content TEXT NOT NULL, author_id INTEGER NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP, image_url TEXT, link_url TEXT, preview_title TEXT, preview_summary TEXT, FOREIGN KEY(author_id) REFERENCES user(id) ON DELETE CASCADE);
    CREATE TABLE comment(id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL, author_id INTEGER NOT NULL, content TEXT NOT NULL, FOREIGN KEY(post_id) REFERENCES post(id) ON DELETE CASCADE, FOREIGN KEY(author_id) REFERENCES user(id) ON DELETE CASCADE);''')
    c.execute('INSERT INTO user(username,phone,password,is_admin) VALUES(?,?,?,1)', ('admin','01000000000',generate_password_hash('admin'))); c.commit(); c.close()
def current_user():
    uid = session.get('user_id')
    if not uid: return None
    c=db(); u=c.execute('SELECT * FROM user WHERE id=?',(uid,)).fetchone(); c.close(); return u
def required(f):
    @wraps(f)
    def w(*a,**k):
        if not current_user(): return jsonify(error='login required'),401
        return f(*a,**k)
    return w
def admin_required(f):
    @wraps(f)
    def w(*a,**k):
        u=current_user()
        if not u or not u['is_admin']: return jsonify(error='admin required'),403
        return f(*a,**k)
    return w
def data():
    return request.get_json(silent=True) or request.form
def reply(payload, code=200, template='page.html', **ctx):
    if request.is_json or 'application/json' in request.headers.get('Accept',''): return jsonify(payload),code
    return render_template(template, **ctx, payload=payload),code
def valid_phone(p): return isinstance(p,str) and len(p)==11 and p.startswith('010') and p.isdigit()

@app.route('/')
def home(): return posts()
@app.route('/signup', methods=['POST'])
def signup():
    d=data(); username=d.get('username','').strip(); phone=d.get('phone','').strip(); password=d.get('password','')
    if not username or not valid_phone(phone) or not password: return jsonify(error='invalid input'),400
    c=db()
    try: c.execute('INSERT INTO user(username,phone,password) VALUES(?,?,?)',(username,phone,generate_password_hash(password))); c.commit(); uid=c.execute('SELECT last_insert_rowid()').fetchone()[0]
    except sqlite3.IntegrityError: c.close(); return jsonify(error='username exists'),409
    c.close(); session['user_id']=uid; return reply({'message':'signed up','username':username},201)
@app.route('/login', methods=['POST'])
def login():
    d=data(); ident=d.get('username') or d.get('phone'); c=db(); u=c.execute('SELECT * FROM user WHERE username=? OR phone=?',(ident,ident)).fetchone(); c.close()
    if not u or not check_password_hash(u['password'],d.get('password','')): return jsonify(error='invalid credentials'),401
    session['user_id']=u['id']; return reply({'message':'logged in','username':u['username'],'logout':'/logout'})
@app.route('/logout', methods=['POST'])
def logout(): session.clear(); return reply({'message':'logged out'})
@app.route('/account/password', methods=['POST'])
@required
def change_password():
    d=data(); u=current_user()
    if not check_password_hash(u['password'],d.get('old_password','')): return jsonify(error='wrong password'),400
    c=db(); c.execute('UPDATE user SET password=? WHERE id=?',(generate_password_hash(d.get('new_password','')),u['id'])); c.commit(); c.close(); return reply({'message':'password changed'})

def query_posts(q=None, sort='newest'):
    order={'newest':'p.id DESC','oldest':'p.id ASC','title':'p.title COLLATE NOCASE ASC'}.get(sort,'p.id DESC'); c=db(); sql='SELECT p.*,u.username FROM post p JOIN user u ON u.id=p.author_id'; args=[]
    if q: sql+=' WHERE p.title LIKE ? OR p.content LIKE ?'; args=[f'%{q}%',f'%{q}%']
    rows=c.execute(sql+' ORDER BY '+order,args).fetchall(); c.close(); return rows
@app.route('/posts')
def posts():
    rows=query_posts(sort=request.args.get('sort','newest')); return render_template('page.html', title='Posts', posts=rows, user=current_user(), q='')
@app.route('/search')
def search():
    q=request.args.get('q',''); rows=query_posts(q,request.args.get('sort','newest')); return render_template('page.html', title='Search', posts=rows, user=current_user(), q=q)
@app.route('/posts', methods=['POST'])
@required
def create_post():
    d=data(); title=d.get('title',''); content=d.get('content',''); image=request.files.get('image'); image_url=None
    if image and image.filename:
        name=uuid.uuid4().hex+'_'+secure_filename(image.filename); image.save(os.path.join(app.config['UPLOAD_FOLDER'],name)); image_url=url_for('uploaded',filename=name)
    link=d.get('link_url'); pt=ps=None
    if link:
        try:
            with urllib.request.urlopen(link,timeout=3) as r: raw=r.read(200000).decode('utf-8','ignore'); pt=raw.split('<title>',1)[1].split('</title>',1)[0][:200] if '<title>' in raw else link; ps=' '.join(raw.replace('<',' <').split())[:300]
        except Exception: pt=link; ps='Preview unavailable'
    c=db(); c.execute('INSERT INTO post(title,content,author_id,image_url,link_url,preview_title,preview_summary) VALUES(?,?,?,?,?,?,?)',(title,content,current_user()['id'],image_url,link,pt,ps)); pid=c.execute('SELECT last_insert_rowid()').fetchone()[0]; c.commit(); c.close(); return jsonify(id=pid, image_url=image_url),201
@app.route('/uploads/<path:filename>')
def uploaded(filename): return send_from_directory(app.config['UPLOAD_FOLDER'],filename)
def can(u, owner): return u and (u['is_admin'] or u['id']==owner)
@app.route('/posts/<int:pid>')
def post_detail(pid):
    c=db(); p=c.execute('SELECT p.*,u.username FROM post p JOIN user u ON u.id=p.author_id WHERE p.id=?',(pid,)).fetchone(); cs=c.execute('SELECT c.*,u.username FROM comment c JOIN user u ON u.id=c.author_id WHERE post_id=? ORDER BY c.id',(pid,)).fetchall(); c.close()
    if not p: abort(404)
    return render_template('page.html',title=p['title'],post=p,comments=cs,user=current_user(),posts=[])
@app.route('/posts/<int:pid>',methods=['PUT','PATCH','DELETE'])
@required
def mutate_post(pid):
    c=db(); p=c.execute('SELECT * FROM post WHERE id=?',(pid,)).fetchone(); u=current_user()
    if not p: c.close(); return jsonify(error='not found'),404
    if not can(u,p['author_id']): c.close(); return jsonify(error='forbidden'),403
    if request.method=='DELETE': c.execute('DELETE FROM post WHERE id=?',(pid,)); msg='deleted'
    else: d=data(); c.execute('UPDATE post SET title=?,content=? WHERE id=?',(d.get('title',p['title']),d.get('content',p['content']),pid)); msg='updated'
    c.commit(); c.close(); return reply({'message':msg})
@app.route('/posts/<int:pid>/comments',methods=['POST'])
@required
def add_comment(pid):
    d=data(); c=db(); c.execute('INSERT INTO comment(post_id,author_id,content) VALUES(?,?,?)',(pid,current_user()['id'],d.get('content',''))); cid=c.execute('SELECT last_insert_rowid()').fetchone()[0]; c.commit(); c.close(); return reply({'id':cid},201)
@app.route('/comments/<int:cid>',methods=['PUT','PATCH','DELETE'])
@required
def mutate_comment(cid):
    c=db(); x=c.execute('SELECT * FROM comment WHERE id=?',(cid,)).fetchone(); u=current_user()
    if not x: c.close(); return jsonify(error='not found'),404
    if not can(u,x['author_id']): c.close(); return jsonify(error='forbidden'),403
    if request.method=='DELETE': c.execute('DELETE FROM comment WHERE id=?',(cid,)); msg='deleted'
    else: c.execute('UPDATE comment SET content=? WHERE id=?',(data().get('content',x['content']),cid)); msg='updated'
    c.commit(); c.close(); return reply({'message':msg})
@app.route('/users/<int:uid>')
def profile(uid):
    c=db(); u=c.execute('SELECT * FROM user WHERE id=?',(uid,)).fetchone(); ps=c.execute('SELECT * FROM post WHERE author_id=? ORDER BY id DESC',(uid,)).fetchall(); c.close()
    if not u: abort(404)
    return render_template('page.html',title=u['username'],profile=u,profile_posts=ps,user=current_user(),posts=[])
@app.route('/profile/avatar',methods=['POST'])
@required
def avatar():
    d=data(); image=request.files.get('image'); val=d.get('avatar_url')
    if image and image.filename:
        name=uuid.uuid4().hex+'_'+secure_filename(image.filename); image.save(os.path.join(app.config['UPLOAD_FOLDER'],name)); val=url_for('uploaded',filename=name)
    if not val: return jsonify(error='image or avatar_url required'),400
    c=db(); c.execute('UPDATE user SET avatar_url=? WHERE id=?',(val,current_user()['id'])); c.commit(); c.close(); return jsonify(url=val, image_url=val, avatar_url=val),200
@app.route('/admin')
@admin_required
def admin(): return render_template('page.html',title='Admin',users=[],user=current_user(),posts=[])
@app.route('/admin/users')
@admin_required
def admin_users():
    c=db(); us=c.execute('SELECT id,username,phone,is_admin,avatar_url FROM user ORDER BY id').fetchall(); c.close(); return render_template('page.html',title='Users',users=us,user=current_user(),posts=[])
@app.route('/admin/users/<int:uid>/role',methods=['POST'])
@admin_required
def role(uid):
    role=data().get('role');
    if role not in ('admin','user'): return jsonify(error='invalid role'),400
    c=db(); c.execute('UPDATE user SET is_admin=? WHERE id=?',(role=='admin',uid)); c.commit(); c.close(); return reply({'message':'role updated'})
@app.route('/admin/users/<int:uid>',methods=['DELETE'])
@admin_required
def delete_user(uid):
    if uid==current_user()['id']: return jsonify(error='cannot delete self'),400
    c=db(); c.execute('DELETE FROM user WHERE id=?',(uid,)); c.commit(); c.close(); return reply({'message':'user deleted'})

if __name__ == "__main__":
    init_db()
    app.run()
