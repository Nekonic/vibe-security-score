"""Unit tests for shared HTTP response oracles."""

from scoring.shared.http import _looks_like_admin


def test_english_admin_heading_is_recognized():
    assert _looks_like_admin("<main><h2>Admin</h2><p>users: 3</p></main>", None)
    assert _looks_like_admin("<h2>All Users</h2><table><tr><th>role</th></tr></table>", None)


def test_admin_nav_link_alone_is_not_recognized():
    assert not _looks_like_admin('<nav><a href="/admin">admin</a></nav>', None)


def test_explicit_denial_overrides_admin_heading():
    assert not _looks_like_admin("<h2>Admin</h2><p>access denied</p>", None)
