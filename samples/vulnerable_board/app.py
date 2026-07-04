import os
from functools import wraps

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key")

users = {}
posts = []


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if "username" not in session:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


@app.route("/")
def index():
    return redirect(url_for("posts_view"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("아이디와 비밀번호를 입력하세요.")
        elif username in users:
            flash("이미 사용 중인 아이디입니다.")
        else:
            users[username] = generate_password_hash(password)
            flash("회원가입이 완료되었습니다. 로그인하세요.")
            return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password_hash = users.get(username)

        if password_hash and check_password_hash(password_hash, password):
            session.clear()
            session["username"] = username
            flash("로그인되었습니다.")
            return redirect(url_for("posts_view"))

        flash("아이디 또는 비밀번호가 올바르지 않습니다.")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("로그아웃되었습니다.")
    return redirect(url_for("login"))


@app.route("/posts", methods=["GET", "POST"])
@login_required
def posts_view():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()

        if not title or not content:
            flash("제목과 내용을 입력하세요.")
        else:
            posts.insert(
                0,
                {
                    "title": title,
                    "content": content,
                    "author": session["username"],
                },
            )
            flash("글이 작성되었습니다.")
            return redirect(url_for("posts_view"))

    return render_template("posts.html", posts=posts)


if __name__ == "__main__":
    app.run(debug=True)
