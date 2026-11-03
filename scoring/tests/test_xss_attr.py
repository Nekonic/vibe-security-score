"""Attribute-breakout detection for avatar_url (luna-4: `<img src={{url}}>`): judged
on parsed on* attributes, so an inert quoted value never trips it."""
from __future__ import annotations

from scoring.checks.A05_injection_xss import _EventHandlerAttrs


def _hits(html, marker="xssattr1"):
    p = _EventHandlerAttrs(marker)
    p.feed(html)
    return p.hits


def test_unquoted_attribute_breakout_is_found():
    assert _hits("<img class=avatar src=x onerror=alert(&#39;xssattr1&#39;)>") == ["onerror"]


def test_quoted_value_is_inert():
    assert _hits('<img src="x onerror=alert(&#39;xssattr1&#39;)">') == []


def test_unrelated_handlers_are_ignored():
    assert _hits('<body onload="init()"><img src="/a.png"></body>') == []
