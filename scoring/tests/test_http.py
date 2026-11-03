"""Unit tests for shared HTTP response oracles."""

from scoring.shared.http import _looks_like_admin


def test_english_admin_heading_is_recognized():
    assert _looks_like_admin("<main><h2>Admin</h2><p>users: 3</p></main>", None)
    assert _looks_like_admin("<h2>All Users</h2><table><tr><th>role</th></tr></table>", None)


def test_admin_nav_link_alone_is_not_recognized():
    assert not _looks_like_admin('<nav><a href="/admin">admin</a></nav>', None)


def test_explicit_denial_overrides_admin_heading():
    assert not _looks_like_admin("<h2>Admin</h2><p>access denied</p>", None)


def test_shows_number_matches_only_a_whole_number():
    from scoring.shared.http import shows_number
    phone = "01012345678"
    assert shows_number("전화 010-1234-5678", phone)
    assert shows_number("<td>010 1234 5678</td>", phone)
    assert shows_number('{"phone": "01012345678"}', phone)
    # Digits of separate things joined by the old digit-stream match:
    assert not shows_number('token 7xq010"> <title>grader12345678</title>', phone)
    assert not shows_number("<h1>010</h1><p>12345678</p>", phone)
    assert not shows_number("9010123456789", phone)  # part of a longer number
    assert not shows_number("anything", "")
