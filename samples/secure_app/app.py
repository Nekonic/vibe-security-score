import os
import sqlite3
from flask import Flask, render_template, request, session, redirect
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

csrf = CSRFProtect(app)

def get_db():
    conn = sqlite3.connect('secure.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)')
    conn.commit()
    conn.close()

@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response

@app.route('/')
def index():
    return '<h1>Login/Register</h1><a href="/register">Register</a> | <a href="/login">Login</a>'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return render_template('register.html', error='Username and password required'), 400

        hashed = generate_password_hash(password)

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
            conn.commit()
            conn.close()
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Username already exists'), 409

        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return render_template('login.html', error='Username and password required'), 400

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user'] = user['username']
            return redirect('/profile')
        return render_template('login.html', error='Invalid credentials'), 401
    return render_template('login.html')

@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect('/login')
    return render_template('profile.html', user=session['user'])

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

if __name__ == '__main__':
    init_db()
    app.run(debug=False)
