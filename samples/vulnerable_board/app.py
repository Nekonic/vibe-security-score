import os
import re
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (
    Flask,
    request,
    redirect,
    session,
    g,
    jsonify,
    render_template,
    abort,
)

app = Flask(__name__)
app.secret_key = 'flask-board-secret-key'

DB_PATH = 'app.db'
UPLOAD_DIR = Path('static/uploads')
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'svg'}

def get_db():
    if 'db' not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON;')
        g.db = conn
    return g.db


@app.teardown_appcontext

def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT


def save_image(file_storage, prefix='file'):
    if not file_storage or not getattr(file_storage, 'filename', ''):
        return None
    filename = secure_filename(file_storage.filename)
    if not filename or not allowed_file(filename):
        return None
    ext = filename.rsplit('.', 1)[1].lower()
    name = f"{prefix}_{uuid.uuid4().hex}.{ext}"
    path = UPLOAD_DIR / name
    file_storage.save(path)
    return f"/static/uploads/{name}"


def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    db = get_db()
    row = db.execute('SELECT * FROM users WHERE id = ?', (uid,)).fetchone()
    return row


def login_user(user):
    session.clear()
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['is_admin'] = bool(user['is_admin'])


def response_payload(title, html_template, context=None):
    if context is None:
        context = {}
    wants_json = request.is_json or request.accept_mimetypes.get('application/json', 0) > 0 and not request.accept_mimetypes.get('text/html', 0)
    if wants_json:
        return jsonify(context), context.get('status', 200)
    status = context.pop('status', 200)
    return render_template(html_template, **context), status


def parse_payload():
    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form.to_dict()
    return data


def is_admin_required():
    user = current_user()
    return user is not None and user['is_admin'] == 1


def require_login():
    if not current_user():
        return False
    return True


def fetch_link_preview(url: str):
    result = {'link_url': url, 'link_preview_title': '', 'link_preview_summary': ''}
    if not url or not url.startswith(('http://', 'https://')):
        return result
    try:
        req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urlopen(req, timeout=1.5) as resp:
            raw = resp.read(200_000).decode(errors='ignore')
            title_match = re.search(r'<title>(.*?)</title>', raw, re.IGNORECASE | re.S)
            if title_match:
                result['link_preview_title'] = re.sub(r'\s+', ' ', title_match.group(1)).strip()
            desc_match = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', raw, re.IGNORECASE | re.S)
            if not desc_match:
                desc_match = re.search(r'<meta[^>]+content=["\'](.*?)["\'][^>]+name=["\']description["\']', raw, re.IGNORECASE | re.S)
            if desc_match:
                result['link_preview_summary'] = re.sub(r'\s+', ' ', desc_match.group(1)).strip()[:300]
    except (URLError, HTTPError, OSError, ValueError):
        return result
    return result


def ensure_post_author_or_admin(post_row):
    user = current_user()
    if not user:
        return False
    if user['is_admin'] == 1:
        return True
    return post_row['author_id'] == user['id']


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    conn.execute('PRAGMA foreign_keys = ON;')
    cur = conn.cursor()

    cur.execute(
        '''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            avatar_url TEXT
        )
        '''
    )

    cur.execute(
        '''
        CREATE TABLE posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            image_url TEXT,
            link_url TEXT,
            link_preview_title TEXT,
            link_preview_summary TEXT,
            FOREIGN KEY(author_id) REFERENCES users(id) ON DELETE CASCADE
        )
        '''
    )

    cur.execute(
        '''
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            author_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
            FOREIGN KEY(author_id) REFERENCES users(id) ON DELETE CASCADE
        )
        '''
    )

    conn.commit()
    conn.close()


def db_get_posts(sort='newest'):
    db = get_db()
    sort_map = {
        'newest': 'p.created_at DESC',
        'oldest': 'p.created_at ASC',
        'title': 'p.title COLLATE NOCASE ASC'
    }
    order_clause = sort_map.get(sort, 'p.created_at DESC')
    query = f'''
        SELECT p.id, p.title, p.content, p.created_at, p.image_url, p.author_id,
               u.username
        FROM posts p
        JOIN users u ON u.id = p.author_id
        ORDER BY {order_clause}
    '''
    rows = db.execute(query).fetchall()
    return rows


@app.route('/')
def index():
    return redirect('/posts')


@app.route('/signup', methods=['POST'])
def signup():
    data = parse_payload()
    username = (data.get('username') or '').strip()
    phone = (data.get('phone') or '').strip()
    password = data.get('password') or ''

    if not username or not phone or not password:
        if request.is_json:
            return jsonify({'error': 'username, phone, password are required'}), 400
        return render_template('signup.html', error='username, phone, password are required'), 400

    if not re.fullmatch(r'010\d{8}', phone):
        msg = 'phone must be 01012345678 format'
        if request.is_json:
            return jsonify({'error': msg}), 400
        return render_template('signup.html', error=msg), 400

    db = get_db()
    user_count = db.execute('SELECT COUNT(*) AS cnt FROM users').fetchone()['cnt']
    is_admin = 1 if user_count == 0 else 0

    try:
        hashed = generate_password_hash(password)
        cur = db.execute(
            'INSERT INTO users (username, phone, password, is_admin) VALUES (?, ?, ?, ?)',
            (username, phone, hashed, is_admin)
        )
        db.commit()
        user = db.execute('SELECT * FROM users WHERE id = ?', (cur.lastrowid,)).fetchone()
        login_user(user)
    except sqlite3.IntegrityError:
        msg = 'username or phone already exists'
        if request.is_json:
            return jsonify({'error': msg}), 409
        return render_template('signup.html', error=msg), 409

    if request.is_json:
        return jsonify({'message': 'signup success', 'user_id': user['id'], 'username': user['username'], 'is_admin': bool(user['is_admin'])}), 201

    return render_template('signup.html', message='signup success', user=user), 201


@app.route('/login', methods=['POST'])
def login():
    data = parse_payload()
    username = (data.get('username') or '').strip()
    phone = (data.get('phone') or '').strip()
    password = data.get('password') or ''

    if not password or (not username and not phone):
        msg = 'username or phone and password are required'
        if request.is_json:
            return jsonify({'error': msg}), 400
        return render_template('login.html', error=msg), 400

    db = get_db()
    if phone:
        user = db.execute('SELECT * FROM users WHERE phone = ?', (phone,)).fetchone()
    else:
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

    if not user or not check_password_hash(user['password'], password):
        msg = 'invalid credentials'
        if request.is_json:
            return jsonify({'error': msg}), 401
        return render_template('login.html', error=msg), 401

    login_user(user)

    if request.is_json:
        return jsonify({'message': 'login success', 'username': user['username']}), 200

    return render_template('login.html', user=user), 200


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    if request.is_json:
        return jsonify({'message': 'logout success'}), 200
    return render_template('login.html', message='logout success'), 200


@app.route('/account/password', methods=['POST'])
def change_password():
    if not require_login():
        return jsonify({'error': 'login required'}) if request.is_json else (render_template('login.html', error='login required'), 401)

    data = parse_payload()
    old_password = data.get('old_password') or ''
    new_password = data.get('new_password') or ''

    if not old_password or not new_password:
        msg = 'old_password and new_password required'
        if request.is_json:
            return jsonify({'error': msg}), 400
        return render_template('login.html', error=msg), 400

    user = current_user()
    db = get_db()
    if not check_password_hash(user['password'], old_password):
        msg = 'old password mismatch'
        if request.is_json:
            return jsonify({'error': msg}), 403
        return render_template('login.html', error=msg), 403

    db.execute('UPDATE users SET password = ? WHERE id = ?', (generate_password_hash(new_password), user['id']))
    db.commit()

    if request.is_json:
        return jsonify({'message': 'password changed'}), 200
    return render_template('login.html', message='password changed'), 200


@app.route('/posts', methods=['GET', 'POST'])
def posts():
    if request.method == 'POST':
        if not require_login():
            return jsonify({'error': 'login required'}) if request.is_json else (render_template('login.html', error='login required'), 401)

        data = parse_payload()
        title = (data.get('title') or '').strip()
        content = (data.get('content') or '').strip()
        link_url = (data.get('link_url') or '').strip()
        image = request.files.get('image') if not request.is_json else None

        if not title or not content:
            msg = 'title and content are required'
            if request.is_json:
                return jsonify({'error': msg}), 400
            return render_template('posts.html', error=msg, posts=db_get_posts(), user=current_user(), sort='newest'), 400

        image_url = save_image(image, prefix='post') if image else None
        link_preview = fetch_link_preview(link_url) if link_url else {'link_url': '', 'link_preview_title': '', 'link_preview_summary': ''}

        db = get_db()
        cur = db.execute(
            '''
            INSERT INTO posts (title, content, author_id, image_url, link_url, link_preview_title, link_preview_summary)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                title,
                content,
                current_user()['id'],
                image_url,
                link_preview['link_url'],
                link_preview['link_preview_title'],
                link_preview['link_preview_summary'],
            )
        )
        db.commit()
        post = db.execute('SELECT * FROM posts WHERE id = ?', (cur.lastrowid,)).fetchone()

        if request.is_json:
            return jsonify({'message': 'created', 'id': post['id']}), 201
        return render_template('post_created.html', post=post, message='created'), 201

    sort = request.args.get('sort', 'newest')
    posts_rows = db_get_posts(sort)
    return render_template('posts.html', posts=posts_rows, user=current_user(), sort=sort)


@app.route('/posts/<int:post_id>', methods=['GET'])
def post_detail(post_id):
    db = get_db()
    post = db.execute(
        '''
        SELECT p.*, u.username
        FROM posts p
        JOIN users u ON u.id = p.author_id
        WHERE p.id = ?
        ''',
        (post_id,)
    ).fetchone()

    if not post:
        abort(404)

    comments = db.execute(
        '''
        SELECT c.*, u.username
        FROM comments c
        JOIN users u ON u.id = c.author_id
        WHERE c.post_id = ?
        ORDER BY c.id DESC
        ''',
        (post_id,)
    ).fetchall()

    return render_template('post_detail.html', post=post, comments=comments, user=current_user())


@app.route('/posts/<int:post_id>', methods=['PUT', 'PATCH'])
def post_update(post_id):
    if not require_login():
        return jsonify({'error': 'login required'}) if request.is_json else (render_template('login.html', error='login required'), 401)

    db = get_db()
    post = db.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    if not post:
        return jsonify({'error': 'post not found'}), 404

    if not ensure_post_author_or_admin(post):
        return jsonify({'error': 'forbidden'}) if request.is_json else (render_template('login.html', error='forbidden'), 403)

    data = parse_payload()
    title = (data.get('title') or '').strip()
    content = (data.get('content') or '').strip()

    db.execute('UPDATE posts SET title = ?, content = ? WHERE id = ?', (title, content, post_id))
    db.commit()

    if request.is_json:
        return jsonify({'message': 'post updated', 'id': post_id}), 200
    return render_template('post_detail.html', post=db.execute('SELECT p.*, u.username FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = ?', (post_id,)).fetchone(), comments=db.execute('SELECT c.*, u.username FROM comments c JOIN users u ON u.id = c.author_id WHERE c.post_id = ?', (post_id,)).fetchall(), user=current_user()), 200


@app.route('/posts/<int:post_id>', methods=['DELETE'])
def post_delete(post_id):
    if not require_login():
        return jsonify({'error': 'login required'}), 401

    db = get_db()
    post = db.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    if not post:
        return jsonify({'error': 'post not found'}), 404
    if not ensure_post_author_or_admin(post):
        return jsonify({'error': 'forbidden'}), 403

    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()
    return jsonify({'message': 'post deleted'}) if request.is_json else (render_template('posts.html', posts=db_get_posts(), user=current_user(), message='post deleted'), 200)


@app.route('/posts/<int:post_id>/comments', methods=['POST'])
def comments_create(post_id):
    if not require_login():
        return jsonify({'error': 'login required'}) if request.is_json else (render_template('login.html', error='login required'), 401)

    db = get_db()
    post = db.execute('SELECT id FROM posts WHERE id = ?', (post_id,)).fetchone()
    if not post:
        return jsonify({'error': 'post not found'}) if request.is_json else (render_template('posts.html', error='post not found', posts=db_get_posts(), user=current_user()), 404)

    data = parse_payload()
    content = (data.get('content') or '').strip()
    if not content:
        msg = 'content required'
        return jsonify({'error': msg}), 400

    cur = db.execute('INSERT INTO comments (post_id, author_id, content) VALUES (?, ?, ?)', (post_id, current_user()['id'], content))
    db.commit()

    if request.is_json:
        return jsonify({'message': 'comment created', 'id': cur.lastrowid}), 201

    comment_row = db.execute(
        'SELECT c.*, u.username FROM comments c JOIN users u ON u.id = c.author_id WHERE c.id = ?',
        (cur.lastrowid,)
    ).fetchone()
    return render_template('post_detail.html', post=db.execute('SELECT p.*, u.username FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = ?', (post_id,)).fetchone(), comments=db.execute('SELECT c.*, u.username FROM comments c JOIN users u ON u.id = c.author_id WHERE c.post_id = ? ORDER BY c.id DESC', (post_id,)).fetchall(), user=current_user(), new_comment=comment_row), 201


@app.route('/comments/<int:comment_id>', methods=['PUT', 'PATCH'])
def comment_update(comment_id):
    if not require_login():
        return jsonify({'error': 'login required'}), 401

    db = get_db()
    comment = db.execute('SELECT * FROM comments WHERE id = ?', (comment_id,)).fetchone()
    if not comment:
        return jsonify({'error': 'comment not found'}), 404

    user = current_user()
    if not (user['is_admin'] == 1 or comment['author_id'] == user['id']):
        return jsonify({'error': 'forbidden'}), 403

    data = parse_payload()
    content = (data.get('content') or '').strip()
    if not content:
        return jsonify({'error': 'content required'}), 400

    db.execute('UPDATE comments SET content = ? WHERE id = ?', (content, comment_id))
    db.commit()
    return jsonify({'message': 'comment updated', 'id': comment_id}), 200


@app.route('/comments/<int:comment_id>', methods=['DELETE'])
def comment_delete(comment_id):
    if not require_login():
        return jsonify({'error': 'login required'}), 401

    db = get_db()
    comment = db.execute('SELECT * FROM comments WHERE id = ?', (comment_id,)).fetchone()
    if not comment:
        return jsonify({'error': 'comment not found'}), 404

    user = current_user()
    if not (user['is_admin'] == 1 or comment['author_id'] == user['id']):
        return jsonify({'error': 'forbidden'}), 403

    db.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    db.commit()
    return jsonify({'message': 'comment deleted'}), 200


@app.route('/search')
def search():
    q = request.args.get('q', '').strip()
    sort = request.args.get('sort', 'newest')

    db = get_db()
    sort_map = {
        'newest': 'p.created_at DESC',
        'oldest': 'p.created_at ASC',
        'title': 'p.title COLLATE NOCASE ASC'
    }
    order_clause = sort_map.get(sort, 'p.created_at DESC')

    like_q = f"%{q}%"
    rows = db.execute(
        f'''
        SELECT p.id, p.title, p.content, p.created_at, p.image_url, p.author_id, u.username
        FROM posts p
        JOIN users u ON u.id = p.author_id
        WHERE p.title LIKE ? OR p.content LIKE ?
        ORDER BY {order_clause}
        ''',
        (like_q, like_q)
    ).fetchall()

    return render_template('search.html', posts=rows, q=q, sort=sort, user=current_user())


@app.route('/users/<int:user_id>')
def user_profile(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        abort(404)

    posts_rows = db.execute('SELECT id, title, created_at FROM posts WHERE author_id = ? ORDER BY created_at DESC', (user_id,)).fetchall()
    viewer = current_user()
    can_view_phone = viewer is not None and viewer['id'] == user_id
    return render_template('user_profile.html', user=user, posts=posts_rows, can_view_phone=can_view_phone)


@app.route('/profile/avatar', methods=['POST'])
def update_avatar():
    if not require_login():
        return jsonify({'error': 'login required'}), 401

    image = request.files.get('image')
    data = parse_payload()
    avatar_url = (data.get('avatar_url') or '').strip()

    if not image and not avatar_url:
        return jsonify({'error': 'image or avatar_url required'}), 400

    url = None
    if image:
        url = save_image(image, prefix='avatar')
        if not url:
            return jsonify({'error': 'invalid image'}), 400
    else:
        url = avatar_url

    db = get_db()
    db.execute('UPDATE users SET avatar_url = ? WHERE id = ?', (url, current_user()['id']))
    db.commit()

    return jsonify({'message': 'avatar updated', 'url': url, 'image_url': url, 'avatar_url': url}), 200


@app.route('/admin')
def admin_page():
    if not is_admin_required():
        return jsonify({'error': 'admin only'}), 403
    db = get_db()
    total_users = db.execute('SELECT COUNT(*) AS c FROM users').fetchone()['c']
    total_posts = db.execute('SELECT COUNT(*) AS c FROM posts').fetchone()['c']
    total_comments = db.execute('SELECT COUNT(*) AS c FROM comments').fetchone()['c']
    return render_template('admin.html', totals={'users': total_users, 'posts': total_posts, 'comments': total_comments}, user=current_user())


@app.route('/admin/users')
def admin_users():
    if not is_admin_required():
        return jsonify({'error': 'admin only'}), 403
    db = get_db()
    rows = db.execute('SELECT * FROM users ORDER BY id ASC').fetchall()
    return render_template('admin_users.html', users=rows, user=current_user())


@app.route('/admin/users/<int:user_id>/role', methods=['POST'])
def admin_change_role(user_id):
    if not is_admin_required():
        return jsonify({'error': 'admin only'}), 403

    data = parse_payload()
    role = (data.get('role') or '').lower()
    if role not in ('admin', 'user'):
        return jsonify({'error': 'role must be admin or user'}), 400

    is_admin = 1 if role == 'admin' else 0
    db = get_db()
    db.execute('UPDATE users SET is_admin = ? WHERE id = ?', (is_admin, user_id))
    db.commit()
    return jsonify({'message': 'role updated', 'user_id': user_id, 'is_admin': bool(is_admin)}), 200


@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    if not is_admin_required():
        return jsonify({'error': 'admin only'}), 403

    if user_id == session.get('user_id'):
        return jsonify({'error': 'cannot delete self'}), 400

    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    return jsonify({'message': 'user deleted'}), 200


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
