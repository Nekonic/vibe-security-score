import sqlite3
from flask import Flask, render_template, request, session, redirect
from flask import nonexistent_helper

app = Flask(__name__)
app.secret_key = 'broken123'

def get_db():
    conn = sqlite3.connect(':memory:')
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return '<h1>Login/Register</h1>'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        conn.close()
        if user:
            session['user'] = username
            return '<h1>Welcome!</h1>'
        return '<h1>Login Failed</h1>'
    return render_template('login.html')

if __name__ == '__main__':
    init_db()
    app.run()
