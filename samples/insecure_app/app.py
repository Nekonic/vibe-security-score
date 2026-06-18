import sqlite3
import hashlib
from flask import Flask, render_template, render_template_string, request, session, redirect

app = Flask(__name__)
app.secret_key = 'supersecret123'

def get_db():
    conn = sqlite3.connect('insecure.db')
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, pwd TEXT)')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return '<h1>Login/Register</h1><a href="/register">Register</a> | <a href="/login">Login</a>'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        pwd = request.form['pwd']
        hashed = hashlib.md5(pwd.encode()).hexdigest()

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(f"INSERT INTO users (name, pwd) VALUES ('{name}', '{hashed}')")
        conn.commit()
        conn.close()

        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['name']
        pwd = request.form['pwd']
        hashed = hashlib.md5(pwd.encode()).hexdigest()

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM users WHERE name='{name}' AND pwd='{hashed}'")
        user = cursor.fetchone()
        conn.close()

        if user:
            session['user'] = name
            return f'<h1>Welcome {name}!</h1>'
        return render_template_string('<p>{{ error }}</p>', error=request.args.get('error', 'Invalid credentials'))
    return render_template('login.html')

@app.route('/profile')
def profile():
    if 'user' in session:
        user_input = request.args.get('msg', '')
        return render_template_string(f'<p>Hello {{{{ user }}}}! Message: {user_input}</p>', user=session['user'])
    return redirect('/login')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
