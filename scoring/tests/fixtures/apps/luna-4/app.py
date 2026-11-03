import os,secrets,sqlite3,uuid,json,urllib.request,re
from pathlib import Path
from functools import wraps
from flask import Flask,request,session,render_template,jsonify,redirect,url_for,send_from_directory
from werkzeug.security import generate_password_hash,check_password_hash
from werkzeug.utils import secure_filename
BASE=Path(__file__).parent; DB=BASE/'board.db'; UP=BASE/'static/uploads'; UP.mkdir(parents=True,exist_ok=True)
app=Flask(__name__); app.config['SECRET_KEY']=os.environ.get('SECRET_KEY') or secrets.token_hex(32)
def con(): c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c
def init_db():
 if DB.exists(): DB.unlink()
 c=con(); c.executescript("""CREATE TABLE user(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,phone TEXT NOT NULL,password TEXT NOT NULL,is_admin INTEGER NOT NULL DEFAULT 0,avatar_url TEXT);
 CREATE TABLE post(id INTEGER PRIMARY KEY,title TEXT NOT NULL,content TEXT NOT NULL,author_id INTEGER NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP,image_url TEXT,link_url TEXT,preview_title TEXT,preview_summary TEXT,FOREIGN KEY(author_id) REFERENCES user(id) ON DELETE CASCADE);
 CREATE TABLE comment(id INTEGER PRIMARY KEY,post_id INTEGER NOT NULL,author_id INTEGER NOT NULL,content TEXT NOT NULL,FOREIGN KEY(post_id) REFERENCES post(id) ON DELETE CASCADE,FOREIGN KEY(author_id) REFERENCES user(id) ON DELETE CASCADE);""")
 c.execute("INSERT INTO user(username,phone,password,is_admin) VALUES(?,?,?,1)",('admin','01000000000',generate_password_hash('admin123'))); c.commit(); c.close()
def cur(): 
 u=session.get('uid')
 if not u:return None
 c=con(); x=c.execute('SELECT * FROM user WHERE id=?',(u,)).fetchone(); c.close(); return x
def inp(): return request.get_json(silent=True) or request.form
def out(x,code=200):
 return (jsonify(x),code) if request.is_json else (render_template('message.html',**x),code)
def need(f):
 @wraps(f)
 def w(*a,**k):
  if not cur(): return out({'error':'login required'},401)
  return f(*a,**k)
 return w
def adm(f):
 @wraps(f)
 def w(*a,**k):
  if not cur() or not cur()['is_admin']: return out({'error':'admin required'},403)
  return f(*a,**k)
 return w
def upload(field):
 f=request.files.get(field)
 if not f or not f.filename:return None
 n=uuid.uuid4().hex+'_'+secure_filename(f.filename); f.save(UP/n); return '/static/uploads/'+n
def prev(link):
 if not link:return None,None
 try:
  s=urllib.request.urlopen(urllib.request.Request(link,headers={'User-Agent':'Board'}),timeout=3).read(40000).decode('utf8','ignore'); t=re.search(r'<title[^>]*>(.*?)</title>',s,re.I|re.S); z=re.sub(r'<[^>]+>',' ',s); return (t.group(1).strip() if t else link),' '.join(z.split())[:240]
 except:return link,'미리보기를 가져오지 못했습니다.'
@app.route('/')
def home():return redirect('/posts')
@app.post('/signup')
def signup():
 d=inp(); u=d.get('username','').strip(); p=d.get('phone','').strip(); pw=d.get('password','')
 if not u or not p or not pw:return out({'error':'all fields required'},400)
 c=con()
 try: x=c.execute('INSERT INTO user(username,phone,password) VALUES(?,?,?)',(u,p,generate_password_hash(pw))); c.commit()
 except sqlite3.IntegrityError:c.close(); return out({'error':'username already exists'},409)
 session['uid']=x.lastrowid;c.close();return out({'message':'signed up','username':u},201)
@app.post('/login')
def login():
 d=inp(); c=con(); u=c.execute('SELECT * FROM user WHERE username=? OR phone=?',(d.get('username') or d.get('phone'),d.get('username') or d.get('phone'))).fetchone(); c.close()
 if not u or not check_password_hash(u['password'],d.get('password','')):return out({'error':'invalid credentials'},401)
 session['uid']=u['id'];return out({'message':'logged in','username':u['username'],'logout':'/logout'})
@app.post('/logout')
def logout():session.clear();return out({'message':'logged out'})
@app.post('/account/password')
@need
def passwd():
 d=inp();u=cur()
 if not check_password_hash(u['password'],d.get('old_password','')):return out({'error':'wrong password'},400)
 c=con();c.execute('UPDATE user SET password=? WHERE id=?',(generate_password_hash(d.get('new_password','')),u['id']));c.commit();c.close();return out({'message':'password changed'})
@app.get('/posts')
def posts():
 s=request.args.get('sort','newest'); col='title' if s=='title' else 'created_at'; dr='ASC' if s in ('title','oldest') else 'DESC';c=con();p=c.execute(f'SELECT p.*,u.username FROM post p JOIN user u ON u.id=p.author_id ORDER BY {col} {dr}').fetchall();c.close();return render_template('posts.html',posts=p,user=cur())
@app.post('/posts')
@need
def addpost():
 d=inp();link=d.get('link_url');t,z=prev(link);c=con();x=c.execute('INSERT INTO post(title,content,author_id,image_url,link_url,preview_title,preview_summary) VALUES(?,?,?,?,?,?,?)',(d.get('title',''),d.get('content',''),cur()['id'],upload('image'),link,t,z));c.commit();c.close();return out({'message':'created','id':x.lastrowid},201)
@app.get('/posts/<int:i>')
def detail(i):
 c=con();p=c.execute('SELECT p.*,u.username FROM post p JOIN user u ON u.id=p.author_id WHERE p.id=?',(i,)).fetchone();cs=c.execute('SELECT c.*,u.username FROM comment c JOIN user u ON u.id=c.author_id WHERE post_id=?',(i,)).fetchall();c.close()
 if not p:return out({'error':'not found'},404)
 return render_template('post.html',post=p,comments=cs,user=cur())
@app.route('/posts/<int:i>',methods=['PUT','PATCH','DELETE'])
@need
def editpost(i):
 c=con();p=c.execute('SELECT * FROM post WHERE id=?',(i,)).fetchone();u=cur()
 if not p:return out({'error':'not found'},404)
 if not(u['is_admin'] or u['id']==p['author_id']):return out({'error':'forbidden'},403)
 if request.method=='DELETE':c.execute('DELETE FROM post WHERE id=?',(i,));m='deleted'
 else:d=inp();c.execute('UPDATE post SET title=?,content=? WHERE id=?',(d.get('title',p['title']),d.get('content',p['content']),i));m='updated'
 c.commit();c.close();return out({'message':m})
@app.post('/posts/<int:i>/comments')
@need
def comment(i):
 d=inp();c=con();x=c.execute('INSERT INTO comment(post_id,author_id,content) VALUES(?,?,?)',(i,cur()['id'],d.get('content','')));c.commit();c.close();return out({'message':'comment added','id':x.lastrowid},201)
@app.route('/comments/<int:i>',methods=['PUT','PATCH','DELETE'])
@need
def editcomment(i):
 c=con();x=c.execute('SELECT * FROM comment WHERE id=?',(i,)).fetchone();u=cur()
 if not x:return out({'error':'not found'},404)
 if not(u['is_admin'] or u['id']==x['author_id']):return out({'error':'forbidden'},403)
 if request.method=='DELETE':c.execute('DELETE FROM comment WHERE id=?',(i,));m='deleted'
 else:c.execute('UPDATE comment SET content=? WHERE id=?',(inp().get('content',''),i));m='updated'
 c.commit();c.close();return out({'message':m})
@app.get('/search')
def search():
 q=request.args.get('q','');c=con();p=c.execute('SELECT p.*,u.username FROM post p JOIN user u ON u.id=p.author_id WHERE p.title LIKE ? OR p.content LIKE ?',(f'%{q}%',f'%{q}%')).fetchall();c.close();return render_template('search.html',posts=p,q=q,user=cur())
@app.get('/users/<int:i>')
def profile(i):
 c=con();u=c.execute('SELECT * FROM user WHERE id=?',(i,)).fetchone();p=c.execute('SELECT * FROM post WHERE author_id=?',(i,)).fetchall();c.close()
 if not u:return out({'error':'not found'},404)
 return render_template('profile.html',profile=u,posts=p,user=cur())
@app.post('/profile/avatar')
@need
def avatar():
 d=inp();v=upload('image') or d.get('avatar_url')
 if not v:return out({'error':'image required'},400)
 c=con();c.execute('UPDATE user SET avatar_url=? WHERE id=?',(v,cur()['id']));c.commit();c.close();return out({'url':v,'image_url':v,'avatar_url':v})
@app.get('/admin')
@adm
def admin():return render_template('admin.html',users=allusers(),user=cur())
@app.get('/admin/users')
@adm
def users():return render_template('admin.html',users=allusers(),user=cur())
def allusers():
 c=con();x=c.execute('SELECT * FROM user').fetchall();c.close();return x
@app.post('/admin/users/<int:i>/role')
@adm
def role(i):
 r=inp().get('role');c=con();c.execute('UPDATE user SET is_admin=? WHERE id=?',(r=='admin',i));c.commit();c.close();return out({'message':'role updated'})
@app.delete('/admin/users/<int:i>')
@adm
def deluser(i):
 if i==cur()['id']:return out({'error':'cannot delete yourself'},400)
 c=con();c.execute('DELETE FROM user WHERE id=?',(i,));c.commit();c.close();return out({'message':'user deleted'})
if __name__ == "__main__":
    init_db()
    app.run()

