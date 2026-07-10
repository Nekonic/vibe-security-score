"""Booth-simplified ``createsuperuser``: no username default, no password
validation. Wins over Django's because accounts/submissions precede
django.contrib.auth in INSTALLED_APPS. Overrides scoped via try/finally."""
from __future__ import annotations

from django.contrib.auth.management.commands import createsuperuser as _cs


class Command(_cs.Command):
    help = "슈퍼유저 생성 (부스용: 사용자명 기본값 없음, 비밀번호 검증 없음, 이메일 없음)."

    def handle(self, *args, **options):
        original_get_default = _cs.get_default_username
        original_validate = _cs.validate_password

        _cs.get_default_username = lambda *a, **k: ""
        _cs.validate_password = lambda *a, **k: None
        try:
            return super().handle(*args, **options)
        finally:
            _cs.get_default_username = original_get_default
            _cs.validate_password = original_validate
