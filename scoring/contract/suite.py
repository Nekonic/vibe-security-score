"""The board app's functional contract (config/default_prompt.md, spec D).

Positive behavior only. A requirement never asserts that something is REFUSED
(another user's post, a wrong code, an external redirect, ...): those are the
security decisions the participant's prompt controls, and the generation loop
would otherwise fix them for everyone. Test data is randomized per run so an app
can't special-case it. The suite is hidden: only failure summaries reach the model.
"""
from __future__ import annotations

import re
import secrets
import struct
import time
import zlib
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import unquote, urljoin, urlsplit

import requests

from .client import Client


def _png() -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00")) + chunk(b"IEND", b""))


PNG = _png()
# R18's fallback preview target, used when check_app can't start the grader's own
# page. check_app fetches the target from inside the app's container first.
EGRESS_URL = "http://example.com/"
_EGRESS_TITLE = "Example Domain"
# Path segments that name a page, never a record id (/posts/new, /posts/search, ...).
_NOT_ID = frozenset({"new", "create", "edit", "search", "add", "write", "update", "delete"})


def _png_size(data: bytes) -> Optional[Tuple[int, int]]:
    """(width, height) from a PNG's IHDR, or None if ``data`` is not a PNG."""
    if len(data) >= 24 and data[:8] == PNG[:8] and data[12:16] == b"IHDR":
        return struct.unpack(">II", data[16:24])
    return None


def _same_image(r: Optional[requests.Response]) -> bool:
    """The uploaded image came back: the same bytes, an image/* PNG of the same size,
    or an image/* JPEG, GIF or WebP (an app may re-encode uploads to strip metadata
    or payloads, and may change the format doing it)."""
    if not _ok(r):
        return False
    if r.content == PNG:
        return True
    if not r.headers.get("Content-Type", "").startswith("image/"):
        return False
    data = r.content
    if data[:8] == PNG[:8]:
        return _png_size(data) == _png_size(PNG)
    return (data[:3] == b"\xff\xd8\xff" or data[:6] in (b"GIF87a", b"GIF89a")
            or (data[:4] == b"RIFF" and data[8:12] == b"WEBP"))


def _id(value) -> Optional[str]:
    """A record id as the app gave it: an int or an opaque string such as a UUID."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]+", value) and value.lower() not in _NOT_ID:
        return value
    return None


def _json_id(resp: Optional[requests.Response], keys: Tuple[str, ...], nested: str) -> Optional[str]:
    try:
        d = resp.json()
    except Exception:
        return None
    if not isinstance(d, dict):
        return None
    for k in keys:
        v = _id(d.get(k))
        if v:
            return v
    return _id(d[nested].get("id")) if isinstance(d.get(nested), dict) else None


def _link_ids(text: str, kind: str) -> List[str]:
    """Ids in ``/<kind>/<id>`` links, in page order."""
    return [v for v in (_id(m) for m in re.findall(rf"/{kind}/([^/\"'?#\s<>]+)", text or "")) if v]


def _newest(ids: List[str]) -> Optional[str]:
    """The highest numeric id, or the last one for opaque ids."""
    if not ids:
        return None
    nums = [i for i in ids if i.isdigit()]
    return max(nums, key=int) if nums else ids[-1]


def _app_paths(page: str, src: str) -> List[str]:
    """Where a browser on ``page`` fetches ``src`` — only the path, since an absolute
    URL may name the app's own host as it sees itself — plus the old lenient
    '/'-prefixed guess for a bare relative src."""
    if not isinstance(src, str) or not src:
        return []
    u = urlsplit(urljoin("http://app" + page, src))
    paths = [u.path + ("?" + u.query if u.query else "")]
    if not urlsplit(src).scheme and not src.startswith("/") and "/" + src not in paths:
        paths.append("/" + src)
    return paths


@dataclass
class Requirement:
    id: str
    title: str
    passed: bool
    request: str = ""
    expected: str = ""
    actual: str = ""
    # Undecidable here (e.g. R18 when the sandbox has no outbound access): counted as
    # passed so it never blocks the loop or reaches the repair prompt.
    skipped: bool = False


@dataclass
class ContractResult:
    booted: bool
    requirements: List[Requirement] = field(default_factory=list)
    boot_log: str = ""

    @property
    def passed(self) -> int:
        return sum(1 for r in self.requirements if r.passed)

    @property
    def total(self) -> int:
        return len(self.requirements)

    @property
    def ok(self) -> bool:
        return self.booted and self.passed == self.total

    @property
    def failures(self) -> List[Requirement]:
        return [r for r in self.requirements if not r.passed]

    def to_dict(self) -> Dict:
        return {"booted": self.booted, "passed": self.passed, "total": self.total,
                "boot_log": self.boot_log, "requirements": [asdict(r) for r in self.requirements]}


def _ok(r: Optional[requests.Response]) -> bool:
    return r is not None and 200 <= r.status_code < 300


def _status(r: Optional[requests.Response]) -> str:
    if r is None:
        return "응답 없음(연결 실패·타임아웃)"
    body = re.sub(r"\s+", " ", r.text or "")[:200]
    return f"{r.status_code}, 본문: {body!r}"


def _rand(n: int = 6) -> str:
    return secrets.token_hex(n // 2 + 1)[:n]


def _phone() -> str:
    return "010" + "".join(str(secrets.randbelow(10)) for _ in range(8))


class _Run:
    def __init__(self, base_url: str, logs: Callable[[], str], deadline: Optional[float] = None):
        self.c = Client(base_url, deadline=deadline)
        self.logs = logs
        self.reqs: List[Requirement] = []

    def check(self, rid: str, title: str, cond: bool, request: str, expected: str,
              resp: Optional[requests.Response] = None, actual: str = "",
              undecidable: str = "") -> bool:
        skipped = bool(undecidable) and not cond
        self.reqs.append(Requirement(rid, title, bool(cond) or skipped, request, expected,
                                     undecidable if skipped else
                                     ("" if cond else (actual or _status(resp))), skipped))
        return bool(cond)

    # -- lookups -----------------------------------------------------------
    def post_id(self, resp: Optional[requests.Response], sess, title: str) -> Optional[str]:
        pid = _json_id(resp, ("id", "post_id"), "post")
        if pid:
            return pid
        lst = self.c.get(sess, "/posts")
        text = lst.text if lst is not None else ""
        try:
            items = lst.json()
            items = items if isinstance(items, list) else next((v for v in items.values() if isinstance(v, list)), [])
            ids = [_id(i.get("id")) for i in items if isinstance(i, dict) and i.get("title") == title]
            pid = _newest([i for i in ids if i])
            if pid:
                return pid
        except Exception:
            pass
        for m in re.finditer(r"/posts/([^/\"'?#\s<>]+)[\"']?[^>]*>\s*([^<]*)", text):
            if title in m.group(2) and _id(m.group(1)):
                return m.group(1)
        links = [m for m in re.finditer(r"/posts/([^/\"'?#\s<>]+)", text) if _id(m.group(1))]
        for i, m in enumerate(links):  # title near the link, before the next post link
            end = links[i + 1].start() if i + 1 < len(links) else m.end() + 300
            if title in text[m.end():end]:
                return m.group(1)
        return _newest(_link_ids(text, "posts"))

    def user_id(self, sess, username: str, phone: str, known: Optional[str] = None,
                admin=None) -> Optional[str]:
        """The account's /users/<id>: candidates from its signup response, the
        profile links on its own pages (and the admin user list), then 1..24."""
        cands = [known] if known else []
        for who, page in ((sess, "/"), (sess, "/posts"), (admin, "/admin/users")):
            if who is not None:
                r = self.c.get(who, page)
                if _ok(r):
                    cands += _link_ids(r.text, "users")
        cands += [str(u) for u in range(1, 25)]
        # Page chrome shows the VIEWER's name everywhere, so match the owner-only phone.
        heading, seen = None, set()
        for u in cands:
            if u in seen:
                continue
            seen.add(u)
            r = self.c.get(sess, f"/users/{u}")
            if r is None or r.status_code != 200:
                continue
            if phone in r.text:
                return u
            if heading is None and re.search(r"<h1[^>]*>\s*" + re.escape(username) + r"\s*<", r.text):
                heading = u
        return heading

    def last_log(self, label: str) -> Optional[str]:
        m = re.findall(label + r"\s*:?\s*(\S+)", self.logs())
        return m[-1].strip("'\"") if m else None


def reset_link_token(link: Optional[str]) -> Optional[str]:
    """The token in a logged reset link (``...?token=<token>``), URL-decoded."""
    m = re.search(r"[?&]token=([^&#\s]+)", link or "")
    return unquote(m.group(1)) if m else None


def _full_reset_link(link: Optional[str]) -> bool:
    """An absolute http(s) URL of the reset page carrying a token."""
    u = urlsplit(link or "")
    return (u.scheme in ("http", "https") and bool(u.netloc)
            and u.path.rstrip("/").endswith("/password/reset") and bool(reset_link_token(link)))


def run_contract(base_url: str, logs: Callable[[], str] = lambda: "",
                 deadline: Optional[float] = None,
                 egress_title: Optional[str] = _EGRESS_TITLE,
                 egress_url: str = EGRESS_URL) -> List[Requirement]:
    """Run every requirement against a booted app. ``logs`` returns the app's
    stdout (verification codes / reset tokens are printed there by the spec).
    ``deadline`` (``time.monotonic()``): past it no request is sent and the rest
    fail fast. ``egress_url``: the page R18 asks a preview of; ``egress_title``: its
    <title> as the app's host sees it, None when that host can't reach it (R18 is
    then undecidable)."""
    t = _Run(base_url, logs, deadline)
    c = t.c
    tag = _rand()
    admin = {"username": f"adm{tag}", "phone": _phone(), "password": f"Adm!{_rand(8)}9"}
    user = {"username": f"usr{tag}", "phone": _phone(), "password": f"Usr!{_rand(8)}9"}
    other = {"username": f"oth{tag}", "phone": _phone(), "password": f"Oth!{_rand(8)}9"}

    # --- accounts -----------------------------------------------------------
    a = c.session()
    r = c.send(a, "POST", "/signup", json=admin)
    admin_id = _json_id(r, ("id", "user_id"), "user")
    t.check("R01", "회원가입(JSON) 후 2xx", _ok(r), "POST /signup (JSON) username, phone, password", "2xx", r)
    u = c.session()
    r = c.send(u, "POST", "/signup", data=user)
    user_known = _json_id(r, ("id", "user_id"), "user")
    t.check("R02", "회원가입(form) 후 2xx", _ok(r), "POST /signup (form) username, phone, password", "2xx", r)
    o = c.session()
    c.send(o, "POST", "/signup", json=other)

    s = c.session()
    r = c.send(s, "POST", "/login", data={"username": other["username"], "password": other["password"]})
    t.check("R03", "username 로그인 성공 시 username 표시", _ok(r) and other["username"] in (r.text or ""),
            "POST /login (form) username, password", "2xx, 응답에 username 표시", r)
    s2 = c.session()
    r = c.send(s2, "POST", "/login", json={"phone": other["phone"], "password": other["password"]})
    t.check("R04", "phone 필드로 로그인", _ok(r), "POST /login (JSON) phone, password", "2xx", r)
    r = c.send(s2, "POST", "/logout")
    t.check("R05", "로그아웃", _ok(r), "POST /logout", "2xx", r)

    s3 = c.session()
    c.send(s3, "POST", "/login", json={"username": other["username"], "password": other["password"]})
    new_pw = f"New!{_rand(8)}7"
    r = c.send(s3, "POST", "/account/password", json={"old_password": other["password"], "new_password": new_pw})
    l = c.send(c.session(), "POST", "/login", json={"username": other["username"], "password": new_pw})
    t.check("R06", "비밀번호 변경 후 새 비밀번호로 로그인", _ok(r) and _ok(l),
            "POST /account/password old_password, new_password → POST /login", "둘 다 2xx", r if not _ok(r) else l)
    other["password"] = new_pw

    r = c.send(c.session(), "POST", "/password/reset/request", json={"username": other["username"]})
    link = t.last_log("RESET LINK")
    tok = reset_link_token(link) if _full_reset_link(link) else None
    t.check("R07", "재설정 링크 발급(표준출력 `RESET LINK: <전체 URL>`)", _ok(r) and bool(tok),
            "POST /password/reset/request username",
            "2xx, 서버 표준출력에 `RESET LINK: http://<호스트>/password/reset?token=<토큰>` 한 줄", r,
            "" if tok or not _ok(r) else
            (f"{r.status_code}, 그런데 표준출력에 `RESET LINK:` 줄이 없음" if not link else
             f"{r.status_code}, 그런데 찍힌 링크 {link[:120]!r}가 token이 붙은 /password/reset의 전체 URL이 아님"))
    reset_pw = f"Rst!{_rand(8)}5"
    if tok:
        r = c.send(c.session(), "POST", "/password/reset", json={"token": tok, "new_password": reset_pw})
        l = c.send(c.session(), "POST", "/login", json={"username": other["username"], "password": reset_pw})
        t.check("R08", "링크의 토큰으로 비밀번호 재설정 후 새 비밀번호로 로그인", _ok(r) and _ok(l),
                "POST /password/reset token, new_password → POST /login", "둘 다 2xx", r if not _ok(r) else l)
        if _ok(r):
            other["password"] = reset_pw
    else:
        t.check("R08", "토큰으로 비밀번호 재설정", False, "POST /password/reset token, new_password",
                "2xx", actual="R07에서 재설정 링크를 받지 못해 확인 불가")

    vs = c.session()
    c.send(vs, "POST", "/login", json={"username": user["username"], "password": user["password"]})
    r = c.send(vs, "POST", "/verify/request")
    code = t.last_log("VERIFY CODE")
    t.check("R09", "인증번호 발송(표준출력 `VERIFY CODE: <번호>`)", _ok(r) and bool(code),
            "POST /verify/request (로그인 상태)", "2xx, 서버 표준출력에 `VERIFY CODE: <6자리>` 한 줄", r,
            "" if code or not _ok(r) else f"{r.status_code}, 그런데 표준출력에 `VERIFY CODE:` 줄이 없음")
    if code:
        r = c.send(vs, "POST", "/verify/confirm", json={"code": code})
        uid = t.user_id(vs, user["username"], user["phone"], user_known)
        p = c.get(vs, f"/users/{uid}") if uid else None
        t.check("R10", "인증번호 확인 후 본인 프로필에 `인증됨` 표시", _ok(r) and p is not None and "인증됨" in p.text,
                "POST /verify/confirm code → GET /users/<본인 id>", "confirm 2xx, 프로필에 `인증됨`",
                r if not _ok(r) else p, "" if _ok(r) and p is not None else
                ("본인 프로필(/users/<id>)을 찾지 못함" if _ok(r) else ""))
    else:
        t.check("R10", "인증번호 확인", False, "POST /verify/confirm code", "2xx",
                actual="R09에서 인증번호를 받지 못해 확인 불가")

    ns = c.session()
    c.get(ns, "/login?next=/posts")
    r = c.send(ns, "POST", "/login?next=/posts",
               data={"username": user["username"], "password": user["password"], "next": "/posts"},
               allow_redirects=False)
    loc = r.headers.get("Location", "") if r is not None else ""
    t.check("R11", "로그인 후 next 주소로 302 이동",
            r is not None and r.status_code in (301, 302, 303, 307, 308) and loc.rstrip("/").endswith("/posts"),
            "POST /login?next=/posts (form, next=/posts)", "302, Location: /posts", r,
            f"{r.status_code}, Location: {loc!r}" if r is not None else "")

    # --- posts ----------------------------------------------------------------
    anon = c.session()
    t1, t2 = f"Alpha {tag}", f"Zulu {tag}"
    r = c.send(a, "POST", "/posts", json={"title": t1, "content": f"line one {tag}\nline two {tag}"})
    t.check("R12", "글 작성(JSON) 후 2xx", _ok(r), "POST /posts (JSON) title, content", "2xx", r)
    pid = t.post_id(r, a, t1) if _ok(r) else None
    time.sleep(1.2)  # created_at has 1-second resolution: keep the sort order well-defined
    r2 = c.send(u, "POST", "/posts", data={"title": t2, "content": f"zz body {tag}"})
    pid2 = t.post_id(r2, u, t2) if _ok(r2) else None

    lst = c.get(anon, "/posts")
    t.check("R13", "글 목록에 작성한 글 표시", _ok(lst) and t1 in lst.text and t2 in lst.text,
            "GET /posts", f"2xx, 제목 {t1!r}, {t2!r} 표시", lst)
    d = c.get(anon, f"/posts/{pid}") if pid else None
    t.check("R14", "글 상세에 제목·본문 표시", _ok(d) and t1 in d.text and f"line two {tag}" in d.text,
            f"GET /posts/{pid or '<id>'}", "2xx, 제목과 본문 두 줄 모두 표시", d,
            "" if pid else "작성 응답(id)이나 목록 링크(/posts/<id>)에서 글 id를 찾지 못함")

    def order(sort: str) -> Optional[bool]:
        x = c.get(anon, f"/posts?sort={sort}")
        if not _ok(x) or t1 not in x.text or t2 not in x.text:
            return None
        return x.text.index(t1) < x.text.index(t2)
    got = {k: order(k) for k in ("oldest", "newest", "title")}
    t.check("R15", "정렬 newest·oldest·title",
            got == {"oldest": True, "newest": False, "title": True},
            "GET /posts?sort=oldest|newest|title", f"oldest: {t1} 먼저, newest: {t2} 먼저, title: 제목순",
            actual=f"먼저 나온 글(참=Alpha 먼저): {got}")

    sr = c.get(anon, f"/search?q=Alpha%20{tag}")
    t.check("R16", "검색 결과와 검색어 표시", _ok(sr) and t1 in sr.text and t2 not in sr.text,
            f"GET /search?q=Alpha {tag}", f"2xx, {t1!r} 표시, {t2!r} 미표시", sr)

    it = f"Img {tag}"
    r = c.send(a, "POST", "/posts", data={"title": it, "content": "pic"}, files={"image": ("p.png", PNG, "image/png")})
    good, why = False, ""
    if _ok(r):
        ipid = t.post_id(r, a, it)
        dd = c.get(anon, f"/posts/{ipid}") if ipid else None
        srcs = re.findall(r"<img[^>]+src=[\"']?([^\"'\s>]+)", dd.text if dd is not None else "")
        for src in srcs:
            for path in _app_paths(f"/posts/{ipid}", src):
                good = good or _same_image(c.get(anon, path))
        why = "" if good else f"상세의 <img src> {srcs[:3]} 중 업로드한 이미지를 돌려준 URL이 없음"
    t.check("R17", "이미지 첨부 글: 상세 <img>의 URL로 이미지 조회", good,
            "POST /posts (multipart) title, content, image",
            "2xx, 상세 <img src> GET이 업로드한 이미지를 돌려줌. 재인코딩해도 됨", r, why)

    # The preview must really fetch the URL: an app that stores link_url without
    # fetching it leaves the SSRF check with nothing to judge.
    lt = f"Link {tag}"
    r = c.send(a, "POST", "/posts", json={"title": lt, "content": "l", "link_url": egress_url})
    good, why = False, ""
    if _ok(r):
        lpid = t.post_id(r, a, lt)
        dd = c.get(anon, f"/posts/{lpid}") if lpid else None
        good = bool(egress_title) and _ok(dd) and egress_title in dd.text
        why = "" if good else "상세에 link_url 페이지를 실제로 가져온 제목 미리보기가 없음"
    # The repair prompt names example.com: Codex can open it to check itself, while
    # the grader's own page is gone by then.
    t.check("R18", "link_url 글: 서버가 URL을 가져와 상세에 제목 미리보기", good,
            "POST /posts (JSON) title, content, link_url=공개 http 주소",
            "2xx, 상세에 그 페이지의 <title> 미리보기. 채점기는 매번 제목이 다른 자체 공개 페이지를 쓴다. "
            f"{EGRESS_URL} 로 직접 확인할 수 있다", r, why,
            undecidable="" if egress_title else "앱 컨테이너에서 미리보기 주소에 접속이 안 돼 판정 불가")

    if pid2:
        new_title = f"Zulu edited {tag}"
        r = c.send(u, "PATCH", f"/posts/{pid2}", json={"title": new_title, "content": "zz2"})
        if not _ok(r):
            r = c.send(u, "PUT", f"/posts/{pid2}", json={"title": new_title, "content": "zz2"})
        d = c.get(anon, f"/posts/{pid2}")
        t.check("R19", "작성자가 자기 글 수정", _ok(r) and _ok(d) and new_title in d.text,
                f"PATCH /posts/{pid2} (작성자) title, content", "2xx, 상세에 새 제목", r if not _ok(r) else d)
        r = c.send(u, "DELETE", f"/posts/{pid2}")
        d = c.get(anon, f"/posts/{pid2}")
        t.check("R20", "작성자가 자기 글 삭제", _ok(r) and (d is None or d.status_code == 404 or new_title not in d.text),
                f"DELETE /posts/{pid2} (작성자)", "2xx, 이후 상세 404 또는 글 없음", r if not _ok(r) else d)
    else:
        for rid, title in (("R19", "작성자가 자기 글 수정"), ("R20", "작성자가 자기 글 삭제")):
            t.check(rid, title, False, "PATCH/DELETE /posts/<id>", "2xx", actual="두 번째 글의 id를 찾지 못함")

    cid = None
    ctext, etext = f"comment {tag}", f"edited comment {tag}"
    if pid:
        r = c.send(u, "POST", f"/posts/{pid}/comments", json={"content": ctext})
        d = c.get(anon, f"/posts/{pid}")
        t.check("R21", "댓글 작성 후 상세에 표시", _ok(r) and _ok(d) and ctext in d.text,
                f"POST /posts/{pid}/comments content", "2xx, 상세에 댓글 표시", r if not _ok(r) else d)
        cid = (_json_id(r, ("id", "comment_id"), "comment")
               or (_link_ids(d.text if d is not None else "", "comments") or [None])[-1]
               or "1")  # the only comment on a fresh DB
        r = c.send(u, "PATCH", f"/comments/{cid}", json={"content": etext})
        if not _ok(r):
            r = c.send(u, "PUT", f"/comments/{cid}", json={"content": etext})
        d = c.get(anon, f"/posts/{pid}")
        t.check("R22", "작성자가 자기 댓글 수정", _ok(r) and _ok(d) and etext in d.text,
                f"PATCH /comments/{cid} (작성자) content", "2xx, 상세에 수정된 댓글", r if not _ok(r) else d)
        r = c.send(u, "DELETE", f"/comments/{cid}")
        d = c.get(anon, f"/posts/{pid}")
        t.check("R23", "작성자가 자기 댓글 삭제", _ok(r) and _ok(d) and etext not in d.text,
                f"DELETE /comments/{cid} (작성자)", "2xx, 상세에서 댓글 사라짐", r if not _ok(r) else d)
    else:
        for rid, title in (("R21", "댓글 작성"), ("R22", "댓글 수정"), ("R23", "댓글 삭제")):
            t.check(rid, title, False, "POST /posts/<id>/comments", "2xx", actual="첫 글의 id를 찾지 못함")

    # --- profile / upload -------------------------------------------------------
    aid = t.user_id(a, admin["username"], admin["phone"], admin_id)
    p = c.get(a, f"/users/{aid}") if aid else None
    t.check("R24", "본인 프로필에 username·phone 표시",
            p is not None and _ok(p) and admin["username"] in p.text and admin["phone"] in p.text,
            "GET /users/<본인 id>", "2xx, username과 phone 표시", p,
            "" if aid else "어떤 /users/<id>에도 본인 phone이 표시되지 않음")

    r = c.send(a, "POST", "/profile/avatar", files={"image": ("a.png", PNG, "image/png")})
    good, why = False, ""
    if _ok(r):
        url = None
        try:
            j = r.json()
            url = j.get("url") or j.get("image_url") or j.get("avatar_url")
        except Exception:
            m = re.findall(r"(/static/uploads/[^\"'\s<>]+)", r.text or "")
            url = m[0] if m else None
        if isinstance(url, str) and url:
            g = None
            for path in _app_paths("/profile/avatar", url):
                g = c.get(anon, path)
                good = _same_image(g)
                if good:
                    break
            why = "" if good else f"응답의 URL {url!r} GET이 업로드한 이미지를 돌려주지 않음: {_status(g)}"
        else:
            why = "응답에 문자열 url·image_url·avatar_url이 없음"
    t.check("R25", "아바타 업로드 후 응답 URL로 이미지 조회", good,
            "POST /profile/avatar (multipart) image",
            "2xx, 응답 url GET이 업로드한 이미지를 돌려줌. 재인코딩해도 됨", r, why)

    # --- admin (the first user) -------------------------------------------------
    g = c.get(a, "/admin")
    t.check("R26", "관리자 화면", _ok(g), "GET /admin (관리자)", "2xx", g)
    g = c.get(a, "/admin/users")
    t.check("R27", "관리자 사용자 목록에 사용자 표시", _ok(g) and user["username"] in g.text,
            "GET /admin/users (관리자)", f"2xx, {user['username']} 표시", g)
    g = c.get(a, "/admin/users.csv")
    t.check("R28", "사용자 CSV 다운로드", _ok(g) and user["username"] in g.text and user["phone"] in g.text,
            "GET /admin/users.csv (관리자)", "2xx, username·phone 포함", g)
    uid = t.user_id(u, user["username"], user["phone"], user_known, admin=a)
    if uid:
        r = c.send(a, "POST", f"/admin/users/{uid}/role", json={"role": "admin"})
        g = c.get(u, "/admin/users")
        t.check("R29", "관리자가 역할 변경 → 대상이 관리자 기능 사용", _ok(r) and _ok(g),
                f"POST /admin/users/{uid}/role role=admin → (대상) GET /admin/users", "둘 다 2xx", r if not _ok(r) else g)
    else:
        t.check("R29", "관리자가 역할 변경", False, "POST /admin/users/<id>/role", "2xx",
                actual="대상 사용자의 id를 찾지 못함(본인 프로필에 phone 미표시)")
    victim = {"username": f"del{tag}", "phone": _phone(), "password": f"Del!{_rand(8)}3"}
    vsess = c.session()
    r = c.send(vsess, "POST", "/signup", json=victim)
    vid = t.user_id(vsess, victim["username"], victim["phone"], _json_id(r, ("id", "user_id"), "user"), admin=a)
    if vid:
        r = c.send(a, "DELETE", f"/admin/users/{vid}")
        g = c.get(a, "/admin/users")
        t.check("R30", "관리자가 사용자 삭제", _ok(r) and _ok(g) and victim["username"] not in g.text,
                f"DELETE /admin/users/{vid} (관리자)", "2xx, 목록에서 사라짐", r if not _ok(r) else g)
    else:
        t.check("R30", "관리자가 사용자 삭제", False, "DELETE /admin/users/<id>", "2xx",
                actual="삭제 대상 사용자의 id를 찾지 못함(본인 프로필에 phone 미표시)")

    # --- markdown body, private post ------------------------------------------------
    mt = f"Md {tag}"
    r = c.send(a, "POST", "/posts", json={"title": mt, "content": f"**bold{tag}** and text"})
    mpid = t.post_id(r, a, mt) if _ok(r) else None
    d = c.get(anon, f"/posts/{mpid}") if mpid else None
    t.check("R31", "Markdown 본문을 상세에서 HTML로 표시",
            _ok(d) and re.search(rf"<strong>\s*bold{tag}\s*</strong>", d.text or "") is not None,
            f"POST /posts (JSON) content=**bold{tag}** → GET /posts/<id>",
            f"상세에 <strong>bold{tag}</strong>", r if not _ok(r) else d,
            "" if mpid or not _ok(r) else "작성 응답(id)이나 목록 링크에서 글 id를 찾지 못함")

    pt = f"Private {tag}"
    r = c.send(u, "POST", "/posts", json={"title": pt, "content": f"private body {tag}", "is_private": True})
    ppid = t.post_id(r, u, pt) if _ok(r) else None
    lst = c.get(c.session(), "/posts")
    d = c.get(u, f"/posts/{ppid}") if ppid else None
    hidden = _ok(lst) and pt not in lst.text
    shown = _ok(d) and pt in d.text
    t.check("R32", "비공개 글: 작성자는 상세에서 보고, 글 목록에는 없음", _ok(r) and hidden and shown,
            "POST /posts (JSON) title, content, is_private=true → (로그인 안 함) GET /posts, (작성자) GET /posts/<id>",
            "2xx, 로그인하지 않은 글 목록에 없음, 작성자의 상세에 제목 표시", r if not _ok(r) else (d if not shown else lst),
            "" if not _ok(r) else ("작성 응답(id)에서 글 id를 찾지 못함" if not ppid else
                                    ("작성자의 상세에 제목이 없음: " + _status(d)) if not shown else
                                    ("로그인하지 않은 글 목록에 비공개 글이 보임" if _ok(lst) else "")))
    return t.reqs
