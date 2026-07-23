"""Unit tests for the shared CSRF helper.

Pin two fixes that unblocked correctly-hardened apps:
  1) ``extract_csrf`` must recognize the ``_csrf`` field name (used by many
     hand-rolled Flask apps), not only ``csrf_token`` — it is already accepted as a
     JSON key, so recognizing it only in JSON but not in HTML forms meant the token
     could never be re-seeded from a GET page.
  2) ``post_with_csrf`` must not permanently blank the session token on a rejection
     when re-seeding turns up nothing (a validation-400 is not a CSRF failure).
"""
from __future__ import annotations

from scoring.shared import csrf


class _Resp:
    def __init__(self, status: int, text: str = "", json=None):
        self.status_code = status
        self._text = text
        self._json = json

    @property
    def text(self) -> str:
        return self._text

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


# ---- extract_csrf: field-name variants ------------------------------------
def test_extract_csrf_underscore_field_from_html():
    body = '<form><input type="hidden" name="_csrf" value="TOKA1"></form>'
    assert csrf.extract_csrf(_Resp(200, body)) == "TOKA1"


def test_extract_csrf_underscore_field_value_first():
    body = '<input value="TOKB2" name="_csrf">'
    assert csrf.extract_csrf(_Resp(200, body)) == "TOKB2"


def test_extract_csrf_csrf_token_field_still_works():
    body = '<input name="csrf_token" value="TOKC3">'
    assert csrf.extract_csrf(_Resp(200, body)) == "TOKC3"


def test_extract_csrf_meta_underscore():
    body = '<meta name="_csrf" content="TOKD4">'
    assert csrf.extract_csrf(_Resp(200, body)) == "TOKD4"


def test_extract_csrf_json_key():
    assert csrf.extract_csrf(_Resp(200, json={"csrf_token": "TOKE5"})) == "TOKE5"


# ---- post_with_csrf: token retention on a non-CSRF rejection ---------------
def _session_token_holder(initial=""):
    box = {"tok": initial}
    return box


def test_post_with_csrf_keeps_prior_token_when_reseed_finds_none():
    # App returns 400 for a VALIDATION reason (not CSRF) and its pages don't expose a
    # token the extractor can read (reseed is a no-op). The session's known-good token
    # must survive rather than being blanked to "" (which would 403 every later call).
    box = _session_token_holder("PREVTOK")

    def post(url, **kw):
        return _Resp(400, "bad file type")  # never a 2xx, no token in body

    def reseed():
        return None  # can't discover a token from GET pages

    csrf.post_with_csrf(
        post, "http://x/upload", {"f": 1},
        get_token=lambda: box["tok"],
        set_token=lambda t: box.__setitem__("tok", t),
        reseed=reseed,
    )
    assert box["tok"] == "PREVTOK"  # not blanked


def test_post_with_csrf_adopts_reseeded_token():
    box = _session_token_holder("STALE")

    def post(url, **kw):
        # Reject the stale token, accept the freshly reseeded one.
        sent = (kw.get("json") or kw.get("data") or {}).get(csrf.CSRF_FIELD)
        return _Resp(200, "ok") if sent == "FRESH" else _Resp(403, "csrf")

    def reseed():
        box["tok"] = "FRESH"

    r = csrf.post_with_csrf(
        post, "http://x/action", {"f": 1},
        get_token=lambda: box["tok"],
        set_token=lambda t: box.__setitem__("tok", t),
        reseed=reseed,
    )
    assert r is not None and r.status_code == 200
    assert box["tok"] == "FRESH"
