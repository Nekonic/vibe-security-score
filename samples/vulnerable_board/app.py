import os
import sqlite3
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
DB = os.path.join(os.path.dirname(__file__), "board.sqlite3")


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_=None):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def init_db():
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )
    exists = conn.execute("SELECT id FROM users WHERE id = 1").fetchone()
    if not exists:
        conn.execute(
            "INSERT INTO users(id, username, email, password, is_admin) VALUES(1, ?, ?, ?, 1)",
            ("admin", "admin@example.com", generate_password_hash("admin")),
        )
    conn.commit()


@app.before_request
def before_request():
    init_db()
    uid = session.get("user_id")
    g.user = db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone() if uid else None


def data():
    return request.get_json(silent=True) or request.form


def wants_json():
    return request.is_json or request.accept_mimetypes["application/json"] >= request.accept_mimetypes["text/html"]


def respond(template, **ctx):
    if wants_json():
        out = {}
        for k, v in ctx.items():
            if isinstance(v, sqlite3.Row):
                out[k] = dict(v)
            elif isinstance(v, list):
                out[k] = [dict(x) if isinstance(x, sqlite3.Row) else x for x in v]
            else:
                out[k] = v
        return jsonify(out)
    return render_template(template, **ctx)


def login_required(fn):
    @wraps(fn)
    def wrap(*args, **kwargs):
        if not g.user:
            return (jsonify(error="login required"), 401) if wants_json() else redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrap


def admin_required(fn):
    @wraps(fn)
    def wrap(*args, **kwargs):
        if not g.user or not g.user["is_admin"]:
            return (jsonify(error="admin required"), 403) if wants_json() else ("Forbidden", 403)
        return fn(*args, **kwargs)
    return wrap


@app.route("/")
def index():
    return redirect(url_for("posts"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")
    d = data()
    try:
        conn = db()
        conn.execute(
            "INSERT INTO users(username, email, password) VALUES(?, ?, ?)",
            (d["username"], d["email"], generate_password_hash(d["password"])),
        )
        conn.commit()
    except (KeyError, sqlite3.IntegrityError) as e:
        return jsonify(error=str(e)), 400
    return jsonify(ok=True)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    d = data()
    ident, password = d.get("username") or d.get("email"), d.get("password", "")
    user = db().execute("SELECT * FROM users WHERE username = ? OR email = ?", (ident, ident)).fetchone()
    if not user or not check_password_hash(user["password"], password):
        return jsonify(error="invalid credentials"), 401
    session["user_id"] = user["id"]
    return jsonify(ok=True, user={"id": user["id"], "username": user["username"], "email": user["email"], "is_admin": user["is_admin"]})


@app.post("/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.route("/posts", methods=["GET", "POST"])
def posts():
    conn = db()
    if request.method == "POST":
        if not g.user:
            return jsonify(error="login required"), 401
        d = data()
        try:
            conn.execute("INSERT INTO posts(title, content, user_id) VALUES(?, ?, ?)", (d["title"], d["content"], g.user["id"]))
            conn.commit()
        except KeyError as e:
            return jsonify(error=f"missing {e}"), 400
        return jsonify(ok=True)
    rows = conn.execute(
        """
        SELECT p.id, p.title, p.content, u.id AS author_id, u.username AS author
        FROM posts p JOIN users u ON u.id = p.user_id
        ORDER BY p.id DESC
        """
    ).fetchall()
    return respond("posts.html", posts=rows)


@app.get("/search")
def search():
    q = request.args.get("q", "")
    rows = db().execute(
        """
        SELECT p.id, p.title, p.content, u.id AS author_id, u.username AS author
        FROM posts p JOIN users u ON u.id = p.user_id
        WHERE p.title LIKE ? OR p.content LIKE ?
        ORDER BY p.id DESC
        """,
        (f"%{q}%", f"%{q}%"),
    ).fetchall()
    return respond("posts.html", posts=rows, q=q)


@app.get("/users/<int:user_id>")
def user_profile(user_id):
    user = db().execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return (jsonify(error="not found"), 404) if wants_json() else ("Not found", 404)
    posts = db().execute("SELECT id, title, content FROM posts WHERE user_id = ? ORDER BY id DESC", (user_id,)).fetchall()
    return respond("user.html", user=user, posts=posts)


@app.get("/admin")
@admin_required
def admin():
    users = db().execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    posts = db().execute("SELECT COUNT(*) AS c FROM posts").fetchone()["c"]
    return respond("admin.html", users=users, posts=posts)


@app.get("/admin/users")
@admin_required
def admin_users():
    users = db().execute("SELECT id, username, email, is_admin FROM users ORDER BY id").fetchall()
    return respond("admin_users.html", users=users)


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=True)
