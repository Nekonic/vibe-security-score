"""Spec-D probe fixture (test_spec_d_probes.py). MODE = "vuln" makes every
candidate decision vulnerable; "safe" defends them all. Only the routes the probes use."""
import csv, html, io, json, os, pickle, random, re, secrets, sqlite3

import markdown
from flask import Flask, Response, abort, jsonify, redirect, request, send_from_directory, session

MODE = "vuln"
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
UP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "uploads")
DB = "ref.db"


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    os.makedirs(UP, exist_ok=True)
    c = db()
    c.executescript("""CREATE TABLE user(id INTEGER PRIMARY KEY, username TEXT UNIQUE, phone TEXT, password TEXT,
      is_admin INTEGER, phone_verified INTEGER DEFAULT 0);
    CREATE TABLE post(id INTEGER PRIMARY KEY, title TEXT, content TEXT, author_id INTEGER, image_url TEXT);
    CREATE TABLE code(user_id INTEGER, code TEXT, tries INTEGER DEFAULT 0);
    CREATE TABLE reset(token TEXT, user_id INTEGER, used INTEGER DEFAULT 0);""")
    c.commit()


def body():
    return request.get_json(silent=True) or request.form


def me():
    uid = session.get("uid")
    u = db().execute("SELECT * FROM user WHERE id=?", (uid,)).fetchone() if uid else None
    if u and MODE == "safe" and session.get("uname") != u["username"]:
        return None  # a deleted user's cookie must not fit whoever gets the id next
    return u


def login_as(uid, username):
    session.clear()
    session["uid"] = uid
    session["uname"] = username


@app.post("/signup")
def signup():
    d = body()
    c = db()
    first = c.execute("SELECT COUNT(*) FROM user").fetchone()[0] == 0
    cur = c.execute("INSERT INTO user(username,phone,password,is_admin) VALUES(?,?,?,?)",
                    (d["username"], d["phone"], d["password"], 1 if first else 0))
    c.commit()
    login_as(cur.lastrowid, d["username"])
    return jsonify(id=cur.lastrowid), 201


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return '<form method="post"><input name="username"></form>'
    d = body()
    u = db().execute("SELECT * FROM user WHERE username=? AND password=?", (d.get("username"), d.get("password"))).fetchone()
    if not u:
        return "bad", 401
    login_as(u["id"], u["username"])
    nxt = request.args.get("next") or d.get("next")
    if nxt:
        if MODE == "safe" and (not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt):
            nxt = "/"
        return redirect(nxt)
    return f"hello {u['username']} <a href=/logout>logout</a>"


@app.route("/posts", methods=["GET", "POST"])
def posts():
    c = db()
    if request.method == "GET":
        rows = c.execute("SELECT * FROM post").fetchall()
        return "".join(f'<a href="/posts/{r["id"]}">{html.escape(r["title"])}</a>' for r in rows)
    u = me()
    if not u:
        abort(401)
    d = body()
    img = None
    f = request.files.get("image")
    if f:
        name = secrets.token_hex(8) + ".png"
        f.save(os.path.join(UP, name))
        img = "/static/uploads/" + name
    cur = c.execute("INSERT INTO post(title,content,author_id,image_url) VALUES(?,?,?,?)",
                    (d["title"], d.get("content", ""), u["id"], img))
    c.commit()
    return jsonify(id=cur.lastrowid), 201


@app.get("/posts/<int:i>")
def detail(i):
    p = db().execute("SELECT * FROM post WHERE id=?", (i,)).fetchone()
    if not p:
        abort(404)
    src = p["content"]
    if MODE == "safe":
        body_html = markdown.markdown(html.escape(src))
        body_html = re.sub(r'href="javascript:[^"]*"', 'href="#"', body_html, flags=re.I)
    else:
        body_html = markdown.markdown(src)
    img = f'<img src="{p["image_url"]}">' if p["image_url"] else ""
    return f"<h1>{html.escape(p['title'])}</h1>{img}<div>{body_html}</div>"


@app.get("/files/<path:name>")
def files(name):
    if MODE == "safe":
        return send_from_directory(UP, name, as_attachment=True)
    return Response(open(os.path.join(UP, name), "rb").read())


@app.get("/posts/export")
def export():
    u = me()
    rows = [dict(title=r["title"], content=r["content"]) for r in db().execute("SELECT * FROM post WHERE author_id=?", (u["id"],))]
    data = json.dumps(rows).encode() if MODE == "safe" else pickle.dumps(rows)
    return Response(data, mimetype="application/octet-stream")


@app.post("/posts/import")
def imp():
    u = me()
    raw = request.files["file"].read()
    try:
        rows = json.loads(raw) if MODE == "safe" else pickle.loads(raw)
    except Exception:
        return "bad", 400
    c = db()
    for r in rows if isinstance(rows, list) else []:
        c.execute("INSERT INTO post(title,content,author_id) VALUES(?,?,?)", (r["title"], r["content"], u["id"]))
    c.commit()
    return jsonify(ok=True), 201


@app.post("/verify/request")
def vreq():
    u = me()
    code = f"{secrets.randbelow(10**6):06d}" if MODE == "safe" else f"{random.randint(0, 999999):06d}"
    c = db()
    c.execute("DELETE FROM code WHERE user_id=?", (u["id"],))
    c.execute("INSERT INTO code(user_id,code) VALUES(?,?)", (u["id"], code))
    c.commit()
    if MODE != "safe":
        session["vcode"] = code
    print(f"VERIFY CODE: {code}", flush=True)
    return jsonify(ok=True)


@app.post("/verify/confirm")
def vconf():
    u = me()
    c = db()
    row = c.execute("SELECT * FROM code WHERE user_id=?", (u["id"],)).fetchone()
    if MODE != "safe":  # the code is kept in the session cookie, compared as given
        row = {"code": session.get("vcode"), "tries": 0}
    if not row:
        return "no code", 400
    if MODE == "safe" and row["tries"] >= 5:
        return "locked", 429
    if body().get("code") != row["code"]:
        c.execute("UPDATE code SET tries=tries+1 WHERE user_id=?", (u["id"],))
        c.commit()
        return "wrong", 400
    c.execute("UPDATE user SET phone_verified=1 WHERE id=?", (u["id"],))
    c.commit()
    return jsonify(ok=True)


@app.get("/users/<int:i>")
def user(i):
    u = db().execute("SELECT * FROM user WHERE id=?", (i,)).fetchone()
    if not u:
        abort(404)
    m = me()
    own = f" {u['phone']}" + (" 인증됨" if u["phone_verified"] else "") if m and m["id"] == i else ""
    return f"<h1>{html.escape(u['username'])}</h1>{own}"


@app.get("/admin/users")
def admin_users():
    u = me()
    if not u or not u["is_admin"]:
        abort(403)
    return "<h1>Admin</h1>" + " ".join(html.escape(r["username"]) for r in db().execute("SELECT username FROM user"))


@app.delete("/admin/users/<int:i>")
def admin_delete(i):
    u = me()
    if not u or not u["is_admin"]:
        abort(403)
    c = db()
    c.execute("DELETE FROM user WHERE id=?", (i,))
    c.commit()
    return jsonify(ok=True)


@app.post("/password/reset/request")
def rreq():
    u = db().execute("SELECT * FROM user WHERE username=?", (body().get("username"),)).fetchone()
    if not u:
        return (jsonify(message="sent"), 200) if MODE == "safe" else ("no such user", 404)
    tok = secrets.token_urlsafe(32) if MODE == "safe" else f"{random.randint(0, 999999):06d}"
    c = db()
    c.execute("INSERT INTO reset(token,user_id) VALUES(?,?)", (tok, u["id"]))
    c.commit()
    print(f"RESET TOKEN: {tok}", flush=True)
    return jsonify(message="sent") if MODE == "safe" else jsonify(message="sent", token=tok)


@app.post("/password/reset")
def rdo():
    d = body()
    c = db()
    row = c.execute("SELECT * FROM reset WHERE token=?", (d.get("token"),)).fetchone()
    if not row or (MODE == "safe" and row["used"]):
        return "bad", 400
    c.execute("UPDATE user SET password=? WHERE id=?", (d["new_password"], row["user_id"]))
    c.execute("UPDATE reset SET used=1 WHERE token=?", (d["token"],))
    c.commit()
    return jsonify(ok=True)


@app.get("/admin/users.csv")
def users_csv():
    u = me()
    if not u or not u["is_admin"]:
        abort(403)
    out = io.StringIO()
    w = csv.writer(out)
    for r in db().execute("SELECT username, phone FROM user"):
        vals = [r["username"], r["phone"]]
        if MODE == "safe":
            vals = ["'" + v if str(v)[:1] in "=+-@" else v for v in vals]
        w.writerow(vals)
    return Response(out.getvalue(), mimetype="text/csv")


if __name__ == "__main__":
    init_db()
    app.run()
