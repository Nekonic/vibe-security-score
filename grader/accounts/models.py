"""운영자 계정 모델. 이메일은 참가자 Flask 앱 개념이라 운영자에겐 불필요 →
email 컬럼을 DB 수준에서 제거하고, email을 다루지 않는 커스텀 매니저를 쓴다."""
from __future__ import annotations

from django.contrib.auth.models import AbstractUser, UserManager


class OperatorManager(UserManager):
    """email을 다루지 않는 매니저 (username + password만)."""

    def _create_user(self, username, password=None, **extra_fields):
        if not username:
            raise ValueError("username은 필수입니다.")
        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, username, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(username, password, **extra_fields)

    def create_superuser(self, username, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        if extra_fields.get("is_staff") is not True:
            raise ValueError("슈퍼유저는 is_staff=True 여야 합니다.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("슈퍼유저는 is_superuser=True 여야 합니다.")
        return self._create_user(username, password, **extra_fields)


class Operator(AbstractUser):
    # 상속받은 email 필드를 제거 → DB에 email 컬럼이 생성되지 않는다.
    email = None
    # createsuperuser가 email 등 부가 필드를 요구하지 않도록: username + password만.
    REQUIRED_FIELDS: list[str] = []

    objects = OperatorManager()

    class Meta:
        verbose_name = "운영자"
        verbose_name_plural = "운영자"
