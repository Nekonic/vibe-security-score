import os
import re
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    render_template,
    jsonify,
    session,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace-with-a-secure-key'
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'board.db')
UPLOAD_DIR = os.path.join(app.root_path, 'static', 'avatars')
os.makedirs(UPLOAD_DIR, exist_ok=True)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
        except OSError:
            pass

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        '''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
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
            created_at TEXT NOT NULL,
            FOREIGN KEY(author_id) REFERENCES users(id)
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
            FOREIGN KEY(post_id) REFERENCES posts(id),
            FOREIGN KEY(author_id) REFERENCES users(id)
        )
        '''
    )

    admin_username = 'admin'
    admin_email = 'admin@example.com'
    admin_password = generate_password_hash('admin1234')

    cur.execute(
        'INSERT INTO users (id, username, email, password, is_admin, avatar_url) VALUES (1, ?, ?, ?, 1, ?)',
        (admin_username, admin_email, admin_password, '/static/avatars/default.png'),
    )

    now = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
    sample_posts = [
        ('환영합니다', '이 앱은 Flask와 sqlite3로 만든 간단한 게시판입니다.\n로그인 후 글을 작성해 보세요.'),
        ('Markdown-like 줄바꿈', '엔터를 두 번 하지 않아도\n본문은 줄바꿈으로 표시됩니다.'),
    ]

    for title, content in sample_posts:
        cur.execute(
            'INSERT INTO posts (title, content, author_id, created_at) VALUES (?, ?, 1, ?)',
            (title, content, now),
        )

    conn.commit()
    conn.close()


def current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    conn = get_db()
    cur = conn.cursor()
    user = cur.execute(
        'SELECT id, username, email, is_admin, avatar_url FROM users WHERE id = ?', (user_id,)
    ).fetchone()
    conn.close()
    return user


def login_user(user):
    session['user_id'] = user['id']


def logout_user():
    session.pop('user_id', None)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            if wants_json():
                return jsonify({'ok': False, 'error': 'login required'}), 401
            return render_template('login.html', next=request.path), 401
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or not user['is_admin']:
            if wants_json():
                return jsonify({'ok': False, 'error': 'admin required'}), 403
            return render_template('admin.html', error='관리자만 접근할 수 있습니다.'), 403
        return fn(*args, **kwargs)

    return wrapper


def wants_json():
    return request.headers.get('Content-Type', '').startswith('application/json') or request.is_json


def get_payload():
    if request.is_json:
        return request.get_json(silent=True) or {}
    return request.form.to_dict()


def sort_sql(column='created_at'):
    s = (request.args.get('sort') or request.form.get('sort') or '').strip().lower()
    if s == 'oldest':
        return 'created_at ASC'
    if s == 'title':
        return 'LOWER(title) ASC'
    return 'created_at DESC'


def render_if_needed(payload, template_name, context):
    if wants_json():
        return jsonify(payload)
    return render_template(template_name, **context)


def format_text(text):
    if text is None:
        return ''
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\\1</strong>', text)
    text = text.replace('\r\n', '<br>')
    text = text.replace('\n', '<br>')
    return text


def fetch_posts(sort_clause='created_at DESC', q=None):
    conn = get_db()
    cur = conn.cursor()
    base_query = (
        'SELECT p.id, p.title, p.content, p.created_at, u.username as author '
        'FROM posts p JOIN users u ON p.author_id = u.id '
    )

    if q:
        rows = cur.execute(
            base_query + 'WHERE p.title LIKE ? OR p.content LIKE ? ORDER BY ' + sort_clause,
            (f'%{q}%', f'%{q}%'),
        ).fetchall()
    else:
        rows = cur.execute(base_query + 'ORDER BY ' + sort_clause).fetchall()

    conn.close()
    posts = []
    for row in rows:
        posts.append(dict(row))
    return posts


@app.route('/')
def index():
    return redirect(url_for('list_posts'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')

    data = get_payload()
    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip()
    password = (data.get('password') or '').strip()

    if not username or not email or not password:
        err = '모든 값을 입력해 주세요.'
        if wants_json():
            return jsonify({'ok': False, 'error': err}), 400
        return render_template('signup.html', error=err), 400

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            'INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, 0)',
            (username, email, generate_password_hash(password)),
        )
        conn.commit()
        uid = cur.lastrowid
        conn.close()
    except sqlite3.IntegrityError:
        conn.close()
        err = '이미 사용 중인 사용자명 또는 이메일입니다.'
        if wants_json():
            return jsonify({'ok': False, 'error': err}), 409
        return render_template('signup.html', error=err), 409

    user = current_user()
    if user and user['id'] == 1:
        pass
    login_user({'id': uid, 'username': username})

    if wants_json():
        return jsonify({'ok': True, 'id': uid, 'username': username}), 201

    return redirect(url_for('list_posts'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    data = get_payload()
    identifier = (data.get('username') or data.get('email') or '').strip()
    password = (data.get('password') or '').strip()

    if not identifier or not password:
        err = '아이디/이메일과 비밀번호를 입력해 주세요.'
        if wants_json():
            return jsonify({'ok': False, 'error': err}), 400
        return render_template('login.html', error=err), 400

    conn = get_db()
    cur = conn.cursor()
    user = cur.execute(
        'SELECT * FROM users WHERE username = ? OR email = ?', (identifier, identifier)
    ).fetchone()
    conn.close()

    if not user or not check_password_hash(user['password'], password):
        err = '로그인 정보가 일치하지 않습니다.'
        if wants_json():
            return jsonify({'ok': False, 'error': err}), 401
        return render_template('login.html', error=err), 401

    login_user(user)
    if wants_json():
        return jsonify({'ok': True, 'id': user['id'], 'username': user['username']})
    return redirect(url_for('list_posts'))


@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    if wants_json():
        return jsonify({'ok': True})
    return redirect(url_for('login'))


@app.route('/posts', methods=['GET', 'POST'])
def list_posts():
    if request.method == 'GET':
        sort_clause = sort_sql()
        posts = fetch_posts(sort_clause)
        return render_if_needed(
            {'ok': True, 'posts': posts},
            'posts.html',
            {
                'posts': posts,
                'sort': request.args.get('sort', 'newest'),
                'query': None,
                'is_search': False,
                'user': current_user(),
            },
        )

    user = current_user()
    if not user:
        if wants_json():
            return jsonify({'ok': False, 'error': 'login required'}), 401
        return render_template('login.html', error='로그인 후 글쓰기 가능'), 401

    data = get_payload()
    title = (data.get('title') or '').strip()
    content = (data.get('content') or '').strip()

    if not title or not content:
        err = '제목과 내용을 입력해 주세요.'
        if wants_json():
            return jsonify({'ok': False, 'error': err}), 400
        return render_template('posts.html', error=err, posts=fetch_posts(sort_sql()), user=user), 400

    now = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        'INSERT INTO posts (title, content, author_id, created_at) VALUES (?, ?, ?, ?)',
        (title, content, user['id'], now),
    )
    pid = cur.lastrowid
    conn.commit()
    conn.close()

    if wants_json():
        return jsonify({'ok': True, 'id': pid}), 201
    return redirect(url_for('list_posts'))


@app.route('/posts/<int:post_id>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
def post_detail(post_id):
    conn = get_db()
    cur = conn.cursor()
    post = cur.execute(
        'SELECT p.id, p.title, p.content, p.created_at, u.username AS author, u.id AS author_id '
        'FROM posts p JOIN users u ON p.author_id = u.id WHERE p.id = ?',
        (post_id,)
    ).fetchone()

    if not post:
        conn.close()
        if wants_json():
            return jsonify({'ok': False, 'error': 'post not found'}), 404
        return render_template('post_detail.html', error='게시글을 찾을 수 없습니다.'), 404

    if request.method == 'GET':
        comments = cur.execute(
            'SELECT c.id, c.content, u.username AS author FROM comments c '
            'JOIN users u ON c.author_id = u.id WHERE c.post_id = ? ORDER BY c.id ASC',
            (post_id,),
        ).fetchall()
        conn.close()
        post_html = format_text(post['content'])
        if wants_json():
            return jsonify(
                {
                    'ok': True,
                    'post': dict(post),
                    'content_html': post_html,
                    'comments': [dict(r) for r in comments],
                }
            )
        return render_template(
            'post_detail.html',
            post=dict(post),
            content_html=post_html,
            comments=comments,
            user=current_user(),
        )

    user = current_user()
    if not user:
        conn.close()
        if wants_json():
            return jsonify({'ok': False, 'error': 'login required'}), 401
        return render_template('login.html', error='로그인 후 이용 가능합니다.'), 401

    method_override = request.form.get('_method', '').upper() if request.form else ''
    if request.method == 'POST':
        # HTML 폼 호환: _method=PATCH/DELETE로 분기
        method = method_override
        if method not in ('PUT', 'PATCH', 'DELETE'):
            if wants_json():
                return jsonify({'ok': False, 'error': 'method not allowed'}), 405
            return render_template('post_detail.html', post=dict(post), comments=[], user=user, error='잘못된 요청 방식'), 405
    else:
        method = request.method

    if method in ('PUT', 'PATCH'):
        data = get_payload()
        title = (data.get('title') or '').strip()
        content = (data.get('content') or '').strip()

        if not title and not content:
            conn.close()
            msg = 'title 또는 content 중 하나는 필요합니다.'
            if wants_json():
                return jsonify({'ok': False, 'error': msg}), 400
            return render_template('post_detail.html', post=dict(post), comments=[], user=user, error=msg), 400

        if not (user['is_admin'] or user['id'] == post['author_id']):
            conn.close()
            msg = '수정 권한이 없습니다.'
            if wants_json():
                return jsonify({'ok': False, 'error': msg}), 403
            return render_template('post_detail.html', post=dict(post), comments=[], user=user, error=msg), 403

        if not title:
            title = post['title']
        if not content:
            content = post['content']

        cur.execute(
            'UPDATE posts SET title = ?, content = ? WHERE id = ?',
            (title, content, post_id),
        )
        conn.commit()
        conn.close()
        if wants_json():
            return jsonify({'ok': True, 'id': post_id, 'title': title, 'content': content})
        return redirect(url_for('post_detail', post_id=post_id))

    # DELETE
    if not (user['is_admin'] or user['id'] == post['author_id']):
        conn.close()
        msg = '삭제 권한이 없습니다.'
        if wants_json():
            return jsonify({'ok': False, 'error': msg}), 403
        return render_template('post_detail.html', post=dict(post), comments=[], user=user, error=msg), 403

    cur.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
    cur.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    conn.commit()
    conn.close()
    if wants_json():
        return jsonify({'ok': True, 'deleted': post_id})
    return redirect(url_for('list_posts'))


@app.route('/posts/<int:post_id>/comments', methods=['POST'])
@login_required
def add_comment(post_id):
    user = current_user()
    data = get_payload()
    content = (data.get('content') or '').strip()

    if not content:
        if wants_json():
            return jsonify({'ok': False, 'error': 'content required'}), 400
        return redirect(url_for('post_detail', post_id=post_id))

    conn = get_db()
    cur = conn.cursor()
    post = cur.execute('SELECT id FROM posts WHERE id = ?', (post_id,)).fetchone()
    if not post:
        conn.close()
        if wants_json():
            return jsonify({'ok': False, 'error': 'post not found'}), 404
        return render_template('post_detail.html', error='게시글을 찾을 수 없습니다.'), 404

    cur.execute(
        'INSERT INTO comments (post_id, author_id, content) VALUES (?, ?, ?)',
        (post_id, user['id'], content),
    )
    conn.commit()
    conn.close()

    if wants_json():
        return jsonify({'ok': True}), 201
    return redirect(url_for('post_detail', post_id=post_id))


@app.route('/search')
def search():
    q = (request.args.get('q') or '').strip()
    sort_clause = sort_sql()
    posts = fetch_posts(sort_clause, q=q)
    return render_if_needed(
        {'ok': True, 'q': q, 'posts': posts},
        'posts.html',
        {
            'posts': posts,
            'search_query': q,
            'query': q,
            'is_search': True,
            'sort': request.args.get('sort', 'newest'),
            'user': current_user(),
        },
    )


@app.route('/users/<int:user_id>')
def user_profile(user_id):
    conn = get_db()
    cur = conn.cursor()
    user = cur.execute(
        'SELECT id, username, email, avatar_url FROM users WHERE id = ?', (user_id,)
    ).fetchone()

    if not user:
        conn.close()
        if wants_json():
            return jsonify({'ok': False, 'error': 'user not found'}), 404
        return render_template('user_profile.html', error='사용자를 찾을 수 없습니다.'), 404

    posts = cur.execute(
        'SELECT id, title, content, created_at FROM posts WHERE author_id = ? ORDER BY created_at DESC',
        (user_id,),
    ).fetchall()
    conn.close()

    if wants_json():
        return jsonify({'ok': True, 'user': dict(user), 'posts': [dict(r) for r in posts]})

    return render_template(
        'user_profile.html',
        user=user,
        posts=posts,
        user_current=current_user(),
    )


@app.route('/account/password', methods=['POST'])
@login_required
def change_password():
    user = current_user()
    data = get_payload()
    old_pw = (data.get('old_password') or '').strip()
    new_pw = (data.get('new_password') or '').strip()

    if not old_pw or not new_pw:
        if wants_json():
            return jsonify({'ok': False, 'error': 'old_password and new_password required'}), 400
        return render_template('account_password.html', user=user, error='두 비밀번호를 모두 입력해 주세요.'), 400

    conn = get_db()
    cur = conn.cursor()
    row = cur.execute('SELECT password FROM users WHERE id = ?', (user['id'],)).fetchone()
    if not row or not check_password_hash(row['password'], old_pw):
        conn.close()
        if wants_json():
            return jsonify({'ok': False, 'error': 'old password mismatch'}), 400
        return render_template('account_password.html', user=user, error='기존 비밀번호가 일치하지 않습니다.'), 400

    cur.execute('UPDATE users SET password = ? WHERE id = ?', (generate_password_hash(new_pw), user['id']))
    conn.commit()
    conn.close()

    if wants_json():
        return jsonify({'ok': True})
    return render_template('account_password.html', user=user, ok='비밀번호가 변경되었습니다.')


@app.route('/admin')
@admin_required
def admin_dashboard():
    return render_template('admin.html', user=current_user(), users_total=user_count())


def user_count():
    conn = get_db()
    cur = conn.cursor()
    count = cur.execute('SELECT COUNT(*) AS cnt FROM users').fetchone()['cnt']
    conn.close()
    return count


@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db()
    cur = conn.cursor()
    users = cur.execute('SELECT id, username, email, is_admin FROM users ORDER BY id ASC').fetchall()
    conn.close()

    if wants_json():
        return jsonify({'ok': True, 'users': [dict(u) for u in users]})
    return render_template('admin_users.html', users=users, user=current_user())


@app.route('/admin/users/<int:user_id>/role', methods=['POST'])
@admin_required
def admin_user_role(user_id):
    payload = get_payload()
    if request.method != 'POST':
        return jsonify({'ok': False, 'error': 'method not allowed'}), 405

    raw = payload.get('is_admin', payload.get('role', ''))
    try:
        is_admin = int(raw) if str(raw).strip() != '' else int(str(raw).lower() in ('true', '1', 'yes', 'on'))
    except Exception:
        is_admin = 1 if str(raw).strip().lower() in ('true', '1', 'yes', 'on') else 0

    conn = get_db()
    cur = conn.cursor()
    cur.execute('UPDATE users SET is_admin = ? WHERE id = ?', (1 if is_admin else 0, user_id))
    conn.commit()
    conn.close()

    if wants_json():
        return jsonify({'ok': True, 'user_id': user_id, 'is_admin': bool(is_admin)})

    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>', methods=['DELETE', 'POST'])
@admin_required
def admin_user_delete(user_id):
    user = current_user()
    if user['id'] == user_id:
        msg = '자신은 삭제할 수 없습니다.'
        if wants_json():
            return jsonify({'ok': False, 'error': msg}), 400
        return redirect(url_for('admin_users'))

    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM comments WHERE author_id = ?', (user_id,))
    cur.execute('UPDATE posts SET author_id = 1 WHERE author_id = ?', (user_id,))
    cur.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    if wants_json():
        return jsonify({'ok': True, 'deleted': user_id})
    return redirect(url_for('admin_users'))


@app.route('/profile/avatar', methods=['POST'])
@login_required
def set_avatar():
    user = current_user()
    avatar_url = None

    if 'image' in request.files and request.files['image'] and request.files['image'].filename:
        file = request.files['image']
        filename = secure_filename(file.filename)
        if filename:
            saved = os.path.join(UPLOAD_DIR, f'user_{user["id"]}_{filename}')
            file.save(saved)
            avatar_url = '/static/avatars/' + os.path.basename(saved)
    elif request.form.get('avatar_url'):
        avatar_url = request.form.get('avatar_url').strip()

    if request.is_json and request.get_json(silent=True):
        js = request.get_json(silent=True) or {}
        if not avatar_url and js.get('avatar_url'):
            avatar_url = js.get('avatar_url')

    if not avatar_url:
        if wants_json():
            return jsonify({'ok': False, 'error': 'avatar_url or image required'}), 400
        return render_template('account_password.html', user=user, error='아바타 URL 또는 이미지 파일이 필요합니다.'), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute('UPDATE users SET avatar_url = ? WHERE id = ?', (avatar_url, user['id']))
    conn.commit()
    conn.close()

    if wants_json():
        return jsonify({'ok': True, 'avatar_url': avatar_url})
    return redirect(url_for('user_profile', user_id=user['id']))


@app.context_processor

def globals_processor():
    return {
        'current_user': current_user(),
    }


@app.template_filter('nl2br')

def nl2br_filter(value):
    return format_text(value)


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
