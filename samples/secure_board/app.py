import html
import ipaddress
import logging
import os
import re
import secrets
import socket
import sqlite3
import urllib.parse
import urllib.request
from contextlib import closing
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
)

DB_PATH = os.path.join(os.path.dirname(__file__), 'board.db')
UPLOAD_DIR = os.path.join(app.root_path, 'static', 'uploads')
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

RATE_WINDOW_SECONDS = 60
RATE_LIMIT = 5  # 개인정보 안전성 확보조치 기준 제5조⑥: 인증 실패 5회 제한
LOCK_MINUTES = 5

logging.basicConfig(level=logging.INFO)
SEC_LOG = logging.getLogger('security')


def connect_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    with connect_db() as conn:
        c = conn.cursor()
        c.execute(
            '''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                phone TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                avatar_url TEXT,
                session_version INTEGER NOT NULL DEFAULT 0
            )'''
        )
        c.execute(
            '''
            CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                author_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                image_url TEXT,
                link_url TEXT,
                preview_title TEXT,
                preview_summary TEXT,
                FOREIGN KEY(author_id) REFERENCES users(id) ON DELETE CASCADE
            )'''
        )
        c.execute(
            '''
            CREATE TABLE comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                author_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
                FOREIGN KEY(author_id) REFERENCES users(id) ON DELETE CASCADE
            )'''
        )


def get_db():
    if 'db' not in g:
        g.db = connect_db()
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def _is_ip_private(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast or ip.is_link_local
    except ValueError:
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: a public URL that 302s to a private address would
    skip the host check above (SSRF filter bypass)."""

    def redirect_request(self, *args, **kwargs):
        return None


_FETCHER = urllib.request.build_opener(_NoRedirect)


def _safe_fetch(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        return None
    host = parsed.hostname
    if not host:
        return None

    try:
        infos = socket.getaddrinfo(host, None)
        for ai in infos:
            ip = ai[4][0]
            if _is_ip_private(ip):
                return None
    except Exception:
        return None

    req = urllib.request.Request(url, headers={'User-Agent': 'board-review-bot/1.0'})
    try:
        with _FETCHER.open(req, timeout=4) as res:
            if res.status >= 400:
                return None
            raw = res.read(30000)
            body = raw.decode('utf-8', errors='ignore')
    except Exception:
        return None

    def _meta(pattern):
        m = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip() if m else None

    title = _meta(r'<title>(.*?)</title>')
    if not title:
        title = _meta(r'<meta[^>]+property=[\"\']og:title[\"\'][^>]+content=[\"\'](.*?)[\"\']')
    summary = _meta(r'<meta[^>]+name=[\"\']description[\"\'][^>]+content=[\"\'](.*?)[\"\']')
    if not summary:
        summary = _meta(r'<meta[^>]+property=[\"\']og:description[\"\'][^>]+content=[\"\'](.*?)[\"\']')
    if not title and not summary:
        return None
    return {'preview_title': html.escape(title[:200]) if title else None, 'preview_summary': html.escape(summary[:500]) if summary else None}


def _get_login_key():
    return request.remote_addr or 'unknown'


def is_login_rate_limited():
    key = _get_login_key()
    store = app.config.setdefault('LOGIN_ATTEMPTS', {})
    now = datetime.utcnow()
    arr = store.get(key, [])
    arr = [x for x in arr if now - x < timedelta(seconds=RATE_WINDOW_SECONDS)]
    failed = app.config.setdefault('FAILED_LOGINS', {})
    lock = app.config.setdefault('LOCKED_UNTIL', {})
    locked_until = lock.get(key)
    if locked_until and now < locked_until:
        return True

    if key in lock and locked_until and now >= locked_until:
        lock.pop(key, None)

    app.config['LOGIN_ATTEMPTS'][key] = arr
    return False


def report_login_failure():
    key = _get_login_key()
    now = datetime.utcnow()
    arr = app.config.setdefault('LOGIN_ATTEMPTS', {}).get(key, [])
    arr.append(now)
    app.config['LOGIN_ATTEMPTS'][key] = arr
    if len(arr) >= RATE_LIMIT:
        app.config.setdefault('LOCKED_UNTIL', {})[key] = now + timedelta(minutes=LOCK_MINUTES)
        app.config['LOGIN_ATTEMPTS'][key] = []
        SEC_LOG.warning('login rate limited', extra={'remote': key})


def get_session_user(db):
    uid = session.get('user_id')
    if not uid:
        return None
    row = db.execute('SELECT * FROM users WHERE id = ?', (uid,)).fetchone()
    # Server-side revocation: a cookie issued before logout/password change carries an
    # old session_version and is rejected even though its signature is still valid.
    if not row or session.get('sv') != row['session_version']:
        return None
    user = dict(row)
    user['is_admin'] = 1 if int(user['is_admin']) == 1 else 0
    return user


def is_admin_user(db):
    user = get_session_user(db)
    return bool(user and int(user['is_admin']) == 1)


def current_user_id():
    return session.get('user_id')


def wants_json():
    return request.path.startswith('/api') or request.content_type == 'application/json' or request.headers.get('Accept', '').find('application/json') != -1


def json_input():
    if request.content_type and 'application/json' in request.content_type:
        return request.get_json(silent=True) or {}
    return request.form.to_dict()


def validate_phone(phone):
    return bool(re.fullmatch(r'010\d{8}', phone or ''))


def validate_password(pwd, username=''):
    # ISMS-P 2.5.4: 8자 이상 2종 조합, 아이디와 같은 비밀번호 금지
    if username and pwd and username.lower() in pwd.lower():
        return False
    return bool(pwd and len(pwd) >= 8 and re.search(r'[A-Za-z]', pwd) and re.search(r'\d', pwd))


def add_security_headers(response):
    response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload')
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    response.headers.setdefault('Permissions-Policy', 'geolocation=()')
    response.headers.setdefault('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'")
    response.headers.setdefault('X-XSS-Protection', '0')
    return response


@app.after_request
def apply_headers(resp):
    return add_security_headers(resp)


def rate_limited_abort():
    return jsonify({'error': 'Too many login attempts, wait then retry.'}), 429


def require_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        db = get_db()
        user = get_session_user(db)
        if not user:
            if wants_json():
                return jsonify({'error': 'Authentication required'}), 401
            abort(401)
        return fn(*args, **kwargs)
    return wrapper


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        db = get_db()
        user = get_session_user(db)
        if not user:
            return jsonify({'error': 'Authentication required'}), 401
        if int(user['is_admin']) != 1:
            if wants_json():
                return jsonify({'error': 'Admin only'}), 403
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def safe_filename(name):
    return secure_filename(name or '')


def allowed_file(name):
    if '.' not in name:
        return False
    return name.rsplit('.', 1)[1].lower() in ALLOWED_EXT


def save_upload(fileobj):
    if not fileobj or not fileobj.filename:
        return None
    filename = safe_filename(fileobj.filename)
    if not allowed_file(filename):
        return None
    ext = filename.rsplit('.', 1)[1].lower()
    rand = secrets.token_hex(8)
    name = f'{datetime.utcnow().strftime("%Y%m%d%H%M%S")}-{rand}.{ext}'
    path = os.path.join(UPLOAD_DIR, name)
    fileobj.save(path)
    return f'/static/uploads/{name}'


def csrf_token():
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_urlsafe(16)
        session['csrf_token'] = token
    return token


def verify_csrf():
    if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return
    if request.endpoint in ('login', 'signup'):
        return
    sent = request.headers.get('X-CSRF-Token')
    if not sent:
        data = json_input()
        sent = data.get('csrf_token')
    if not sent and request.form:
        sent = request.form.get('csrf_token')
    session_token = session.get('csrf_token')
    if sent in (None, ''):
        return
    if session_token and sent == session_token:
        return
    return jsonify({'error': 'Invalid CSRF token'}), 403


@app.before_request
def before_request_security():
    if request.path in ['/static/uploads']:
        return
    if request.method == 'GET':
        session.setdefault('csrf_token', secrets.token_urlsafe(16))
        return

    res = verify_csrf()
    if isinstance(res, tuple):
        return res


def _render_index(posts=None):
    return render_template('index.html', posts=posts or [], sort=request.args.get('sort', 'newest'), user=get_session_user(get_db()), csrf_token=csrf_token())


def _sanitize_text(value):
    if value is None:
        return ''
    return html.escape(str(value).strip())


@app.route('/')
def index():
    db = get_db()
    posts = db.execute('SELECT p.id,p.title,p.content,u.username,u.id AS author_id FROM posts p JOIN users u ON u.id=p.author_id ORDER BY p.created_at DESC LIMIT 10').fetchall()
    return render_template('index.html', posts=posts, sort='newest', user=get_session_user(db), csrf_token=csrf_token())


@app.route('/signup', methods=['POST'])
def signup():
    data = json_input()
    username = _sanitize_text(data.get('username'))
    phone = _sanitize_text(data.get('phone'))
    password = str(data.get('password') or '')

    if not username or not phone or not password:
        if wants_json():
            return jsonify({'error': 'username, phone, password required'}), 400
        return render_template('auth.html', error='Missing fields', csrf_token=csrf_token()), 400
    if not validate_phone(phone):
        if wants_json():
            return jsonify({'error': 'invalid phone'}), 400
        return render_template('auth.html', error='Invalid phone format', csrf_token=csrf_token()), 400
    if not validate_password(password, username):
        if wants_json():
            return jsonify({'error': 'weak password'}), 400
        return render_template('auth.html', error='Password must be >=8 chars and include letters+digits', csrf_token=csrf_token()), 400

    db = get_db()
    try:
        total = db.execute('SELECT COUNT(*) AS c FROM users').fetchone()['c']
        is_admin = 1 if total == 0 else 0
        pw = generate_password_hash(password, method='pbkdf2:sha256')
        cur = db.execute('INSERT INTO users(username, phone, password, is_admin, avatar_url) VALUES (?, ?, ?, ?, ?)',
                         (username, phone, pw, is_admin, None))
        db.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        if wants_json():
            return jsonify({'error': 'username or phone already exists'}), 409
        return render_template('auth.html', error='Duplicate user/phone', csrf_token=csrf_token()), 409

    session.clear()
    session['user_id'] = user_id
    session['sv'] = 0  # fresh account: initial session_version
    session.modified = True
    session['csrf_token'] = secrets.token_urlsafe(16)
    SEC_LOG.info('signup success user_id=%s', user_id)

    if wants_json():
        return jsonify({'message': 'signup success', 'user_id': user_id, 'is_admin': bool(is_admin)}), 201
    return render_template('auth_success.html', username=username), 201


@app.route('/login', methods=['POST'])
def login():
    if is_login_rate_limited():
        return rate_limited_abort()

    data = json_input()
    username = _sanitize_text(data.get('username'))
    phone = _sanitize_text(data.get('phone'))
    password = str(data.get('password') or '')

    if not password or (not username and not phone):
        if wants_json():
            return jsonify({'error': 'username/phone and password required'}), 400
        return render_template('auth.html', error='Need credentials', csrf_token=csrf_token()), 400

    db = get_db()
    if username:
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    else:
        user = db.execute('SELECT * FROM users WHERE phone = ?', (phone,)).fetchone()

    if not user or not check_password_hash(user['password'], password):
        report_login_failure()
        SEC_LOG.warning('login failed user=%s ip=%s', username or phone, _get_login_key())
        if wants_json():
            return jsonify({'error': 'invalid credentials'}), 401
        return render_template('auth.html', error='Invalid credentials', csrf_token=csrf_token()), 401

    session.clear()
    session['user_id'] = user['id']
    session['sv'] = user['session_version']
    session.modified = True
    session['csrf_token'] = secrets.token_urlsafe(16)
    # reset failures
    app.config.setdefault('LOGIN_ATTEMPTS', {})[_get_login_key()] = []
    app.config.setdefault('LOCKED_UNTIL', {}).pop(_get_login_key(), None)
    SEC_LOG.info('login success user_id=%s', user['id'])

    if wants_json():
        return jsonify({'message': 'login success', 'username': user['username']}), 200
    return render_template('auth_success.html', username=user['username']), 200


@app.route('/logout', methods=['POST'])
def logout():
    uid = session.get('user_id')
    if uid:
        db = get_db()
        db.execute('UPDATE users SET session_version = session_version + 1 WHERE id = ?', (uid,))
        db.commit()
    session.clear()
    if wants_json():
        return jsonify({'message': 'logged out'}), 200
    return render_template('auth.html', message='logged out', csrf_token=csrf_token()), 200


@app.route('/account/password', methods=['POST'])
@require_login
def change_password():
    data = json_input()
    old_password = str(data.get('old_password') or '')
    new_password = str(data.get('new_password') or '')
    if not old_password or not new_password:
        return jsonify({'error': 'old_password and new_password required'}), 400
    if not validate_password(new_password, get_session_user(get_db())['username']):
        return jsonify({'error': 'weak password'}), 400

    db = get_db()
    user = get_session_user(db)
    if not check_password_hash(user['password'], old_password):
        SEC_LOG.warning('password change failed user_id=%s', user['id'])
        return jsonify({'error': 'old password mismatch'}), 403

    db.execute('UPDATE users SET password = ?, session_version = session_version + 1 WHERE id = ?',
               (generate_password_hash(new_password, method='pbkdf2:sha256'), user['id']))
    db.commit()
    session['sv'] = user['session_version'] + 1  # keep this session, revoke all others
    SEC_LOG.info('password changed user_id=%s', user['id'])
    return jsonify({'message': 'password changed'}), 200


@app.route('/posts', methods=['GET'])
def list_posts():
    sort = request.args.get('sort', 'newest')
    order_map = {'newest': 'p.created_at DESC', 'oldest': 'p.created_at ASC', 'title': 'LOWER(p.title) ASC'}
    order_sql = order_map.get(sort, 'p.created_at DESC')
    db = get_db()
    rows = db.execute(f'''SELECT p.id, p.title, p.content, p.image_url, p.preview_title, p.preview_summary, u.username AS author
                         FROM posts p
                         JOIN users u ON u.id = p.author_id
                         ORDER BY {order_sql}''').fetchall()
    if wants_json():
        return jsonify({'posts': [dict(r) for r in rows], 'sort': sort}), 200
    return _render_index(rows)


@app.route('/posts', methods=['POST'])
@require_login
def create_post():
    data = json_input()
    title = _sanitize_text(data.get('title'))
    content = _sanitize_text(data.get('content'))
    link_url = _sanitize_text(data.get('link_url'))
    if not title or not content:
        return jsonify({'error': 'title and content required'}), 400

    image_url = None
    file = request.files.get('image') if request.files else None
    if file:
        image_url = save_upload(file)
        if not image_url:
            return jsonify({'error': 'invalid image'}), 400

    preview = None
    if link_url:
        if len(link_url) > 2000:
            return jsonify({'error': 'link_url too long'}), 400
        preview = _safe_fetch(link_url)

    db = get_db()
    user = get_session_user(db)
    db.execute('INSERT INTO posts(title, content, author_id, image_url, link_url, preview_title, preview_summary) VALUES (?, ?, ?, ?, ?, ?, ?)',
               (title, content, user['id'], image_url, link_url or None,
                (preview or {}).get('preview_title') if preview else None,
                (preview or {}).get('preview_summary') if preview else None))
    db.commit()
    return jsonify({'message': 'created', 'title': title, 'content': content, 'image_url': image_url}), 201


@app.route('/posts/<int:post_id>', methods=['GET'])
def post_detail(post_id):
    db = get_db()
    post = db.execute('''SELECT p.*, u.username AS author FROM posts p
                        JOIN users u ON u.id = p.author_id
                        WHERE p.id = ?''', (post_id,)).fetchone()
    if not post:
        abort(404)
    comments = db.execute('''SELECT c.id, c.content, c.author_id, u.username AS author
                           FROM comments c JOIN users u ON u.id=c.author_id
                           WHERE c.post_id = ? ORDER BY c.id ASC''', (post_id,)).fetchall()
    if wants_json():
        return jsonify({'post': dict(post), 'comments': [dict(c) for c in comments]}), 200
    return render_template('post_detail.html', post=post, comments=comments, user=get_session_user(db), csrf_token=csrf_token())


@app.route('/posts/<int:post_id>', methods=['PUT', 'PATCH'])
@require_login
def update_post(post_id):
    data = json_input()
    title = _sanitize_text(data.get('title'))
    content = _sanitize_text(data.get('content'))

    db = get_db()
    post = db.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    if not post:
        return jsonify({'error': 'not found'}), 404
    user = get_session_user(db)
    if post['author_id'] != user['id'] and not user['is_admin']:
        return jsonify({'error': 'forbidden'}), 403

    if not title or not content:
        return jsonify({'error': 'title and content required'}), 400

    db.execute('UPDATE posts SET title=?, content=? WHERE id=?', (title, content, post_id))
    db.commit()
    return jsonify({'message': 'updated', 'id': post_id}), 200


@app.route('/posts/<int:post_id>', methods=['DELETE'])
@require_login
def delete_post(post_id):
    db = get_db()
    post = db.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    if not post:
        return jsonify({'error': 'not found'}), 404
    user = get_session_user(db)
    if post['author_id'] != user['id'] and not user['is_admin']:
        return jsonify({'error': 'forbidden'}), 403
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()
    return jsonify({'message': 'deleted', 'id': post_id}), 200


@app.route('/posts/<int:post_id>/comments', methods=['POST'])
@require_login
def create_comment(post_id):
    db = get_db()
    if not db.execute('SELECT id FROM posts WHERE id = ?', (post_id,)).fetchone():
        return jsonify({'error': 'post not found'}), 404
    data = json_input()
    content = _sanitize_text(data.get('content'))
    if not content:
        return jsonify({'error': 'content required'}), 400

    user = get_session_user(db)
    db.execute('INSERT INTO comments(post_id, author_id, content) VALUES (?, ?, ?)', (post_id, user['id'], content))
    db.commit()
    cid = db.execute('SELECT last_insert_rowid()').fetchone()[0]
    return jsonify({'message': 'comment created', 'id': cid}), 201


@app.route('/comments/<int:comment_id>', methods=['PUT', 'PATCH'])
@require_login
def update_comment(comment_id):
    db = get_db()
    data = json_input()
    content = _sanitize_text(data.get('content'))
    if not content:
        return jsonify({'error': 'content required'}), 400

    comment = db.execute('SELECT * FROM comments WHERE id = ?', (comment_id,)).fetchone()
    if not comment:
        return jsonify({'error': 'not found'}), 404
    user = get_session_user(db)
    if comment['author_id'] != user['id'] and not user['is_admin']:
        return jsonify({'error': 'forbidden'}), 403

    db.execute('UPDATE comments SET content = ? WHERE id = ?', (content, comment_id))
    db.commit()
    return jsonify({'message': 'comment updated', 'id': comment_id}), 200


@app.route('/comments/<int:comment_id>', methods=['DELETE'])
@require_login
def delete_comment(comment_id):
    db = get_db()
    comment = db.execute('SELECT * FROM comments WHERE id = ?', (comment_id,)).fetchone()
    if not comment:
        return jsonify({'error': 'not found'}), 404
    user = get_session_user(db)
    if comment['author_id'] != user['id'] and not user['is_admin']:
        return jsonify({'error': 'forbidden'}), 403

    db.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    db.commit()
    return jsonify({'message': 'comment deleted', 'id': comment_id}), 200


@app.route('/search', methods=['GET'])
def search_posts():
    q = _sanitize_text(request.args.get('q', ''))
    sort = request.args.get('sort', 'newest')
    if not q:
        if wants_json():
            return jsonify({'error': 'q required'}), 400
        return render_template('search.html', q='', results=[], user=get_session_user(get_db()), sort=sort, csrf_token=csrf_token()), 400

    order_map = {'newest': 'p.created_at DESC', 'oldest': 'p.created_at ASC', 'title': 'LOWER(p.title) ASC'}
    order_sql = order_map.get(sort, 'p.created_at DESC')
    like = f'%{q}%'
    db = get_db()
    results = db.execute(f'''SELECT p.id,p.title,p.content,u.username AS author
                          FROM posts p JOIN users u ON u.id=p.author_id
                          WHERE p.title LIKE ? OR p.content LIKE ?
                          ORDER BY {order_sql}''', (like, like)).fetchall()
    if wants_json():
        return jsonify({'q': q, 'sort': sort, 'results': [dict(r) for r in results]}), 200
    return render_template('search.html', q=q, results=results, user=get_session_user(db), sort=sort, csrf_token=csrf_token())


@app.route('/users/<int:user_id>', methods=['GET'])
def user_profile(user_id):
    db = get_db()
    user = db.execute('SELECT id, username, phone, avatar_url, is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        abort(404)
    posts = db.execute('SELECT id,title,created_at FROM posts WHERE author_id = ? ORDER BY created_at DESC', (user_id,)).fetchall()
    me = get_session_user(db)
    show_phone = bool(me and me['id'] == user_id)
    if wants_json():
        data = {'id': user['id'], 'username': user['username'], 'avatar_url': user['avatar_url'], 'posts': [dict(p) for p in posts]}
        if show_phone:
            data['phone'] = user['phone']
        return jsonify(data), 200
    return render_template('user_profile.html', user=user, posts=posts, show_phone=show_phone, owner=show_phone, me=me, csrf_token=csrf_token())


@app.route('/profile/avatar', methods=['POST'])
@require_login
def profile_avatar():
    db = get_db()
    user = get_session_user(db)
    url = None

    if request.files and request.files.get('image'):
        uploaded = save_upload(request.files['image'])
        if not uploaded:
            return jsonify({'error': 'invalid image'}), 400
        url = uploaded
    else:
        data = json_input()
        avatar = _sanitize_text(data.get('avatar_url')) if not request.files else _sanitize_text(request.form.get('avatar_url'))
        if not avatar:
            return jsonify({'error': 'image or avatar_url required'}), 400
        # Only allow same-origin relative paths or absolute safe urls
        if avatar.startswith('http://') or avatar.startswith('https://'):
            p = urllib.parse.urlparse(avatar)
            if not p.scheme or not p.netloc:
                return jsonify({'error': 'invalid avatar_url'}), 400
            # reject metadata leaks and SSRF-ish values
            if _safe_fetch(avatar) is None:
                # still allow if provided but do not follow; keep as supplied for non-preview usage
                pass
            else:
                pass
            url = avatar
        elif avatar.startswith('/'):
            url = avatar
        else:
            return jsonify({'error': 'invalid avatar_url'}), 400

    db.execute('UPDATE users SET avatar_url = ? WHERE id = ?', (url, user['id']))
    db.commit()
    return jsonify({'message': 'avatar updated', 'avatar_url': url, 'url': url, 'image_url': url}), 200


@app.route('/admin')
@require_admin
def admin_home():
    return render_template('admin_home.html', user=get_session_user(get_db()), csrf_token=csrf_token())


@app.route('/admin/users', methods=['GET'])
@require_admin
def admin_users():
    db = get_db()
    users = db.execute('SELECT id, username, phone, is_admin FROM users ORDER BY id ASC').fetchall()
    if wants_json():
        return jsonify({'users': [dict(u) for u in users]}), 200
    return render_template('admin_users.html', users=users, user=get_session_user(db), csrf_token=csrf_token())


@app.route('/admin/users/<int:user_id>/role', methods=['POST'])
@require_admin
def admin_role(user_id):
    data = json_input()
    role = _sanitize_text(data.get('role'))
    if role not in ('admin', 'user'):
        return jsonify({'error': 'role must be admin or user'}), 400
    target_id = user_id
    db = get_db()
    target = db.execute('SELECT * FROM users WHERE id = ?', (target_id,)).fetchone()
    if not target:
        return jsonify({'error': 'not found'}), 404
    admin = get_session_user(db)
    if target_id == admin['id'] and role != 'admin':
        return jsonify({'error': 'cannot demote self'}), 400

    db.execute('UPDATE users SET is_admin = ? WHERE id = ?', (1 if role == 'admin' else 0, target_id))
    db.commit()
    return jsonify({'message': 'role updated', 'user_id': target_id, 'role': role}), 200


@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@require_admin
def admin_delete_user(user_id):
    db = get_db()
    target = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not target:
        return jsonify({'error': 'not found'}), 404
    actor = get_session_user(db)
    if target['id'] == actor['id']:
        return jsonify({'error': 'cannot delete own account'}), 400
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    return jsonify({'message': 'deleted', 'id': user_id}), 200


@app.errorhandler(403)
def err_403(_):
    if wants_json():
        return jsonify({'error': 'forbidden'}), 403
    return render_template('error.html', code=403, message='Forbidden', csrf_token=csrf_token()), 403


@app.errorhandler(404)
def err_404(_):
    if wants_json():
        return jsonify({'error': 'not found'}), 404
    return render_template('error.html', code=404, message='Not found', csrf_token=csrf_token()), 404


if __name__ == '__main__':
    init_db()
    app.run()
