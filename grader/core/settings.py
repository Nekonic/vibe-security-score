"""Django settings for the vibe-security-score grader."""
from __future__ import annotations

import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Repo root: makes sibling packages codex_runner/ and scoring/ importable and
# config/scoring.yaml reachable when running from grader/.
REPO_ROOT = BASE_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Dev fallback ONLY. Operator MUST set DJANGO_SECRET_KEY in production.
INSECURE_SECRET_KEY = "dev-insecure-CHANGE-ME-set-DJANGO_SECRET_KEY-in-prod"
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", INSECURE_SECRET_KEY)

DEBUG = os.environ.get("DJANGO_DEBUG", "1") not in ("0", "false", "False", "")

_allowed = os.environ.get("DJANGO_ALLOWED_HOSTS", "")
ALLOWED_HOSTS = [h.strip() for h in _allowed.split(",") if h.strip()]
if DEBUG and not ALLOWED_HOSTS:
    ALLOWED_HOSTS = ["localhost", "127.0.0.1", "[::1]"]

INSTALLED_APPS = [
    "accounts",
    # Before django.contrib.auth so its createsuperuser override wins
    # (get_commands() gives priority to the earliest app).
    "submissions.apps.SubmissionsConfig",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

# Operator accounts have no email column (email is a participant-app concept).
AUTH_USER_MODEL = "accounts.Operator"

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "core.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "core.wsgi.application"
ASGI_APPLICATION = "core.asgi.application"

# Default: sqlite (dev/test). For prod set DJANGO_DB_* to Postgres (better for
# threaded/parallel scoring writes).
_db_engine = os.environ.get("DJANGO_DB_ENGINE", "django.db.backends.sqlite3")
if _db_engine == "django.db.backends.sqlite3":
    DATABASES = {
        "default": {
            "ENGINE": _db_engine,
            "NAME": os.environ.get(
                "DJANGO_DB_NAME", str(BASE_DIR / "db.sqlite3")
            ),
            # Give writers a chance to wait out a busy lock (dev only).
            "OPTIONS": {"timeout": 20},
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": _db_engine,
            "NAME": os.environ.get("DJANGO_DB_NAME", "grader"),
            "USER": os.environ.get("DJANGO_DB_USER", ""),
            "PASSWORD": os.environ.get("DJANGO_DB_PASSWORD", ""),
            "HOST": os.environ.get("DJANGO_DB_HOST", ""),
            "PORT": os.environ.get("DJANGO_DB_PORT", ""),
        }
    }

# No password strength requirements — operators run this on their own terms and
# customize as they like. Add Django's validators back here if you want a minimum.
AUTH_PASSWORD_VALIDATORS: list = []

# --- Access control (public deployment) --------------------------------------
# No public signup: operators create accounts (createsuperuser / Django admin) and
# hand them out. Pages are viewable (for the booth screen), but SUBMITTING requires
# login — the submit form only shows to logged-in accounts. Session lasts 10 hours
# (a booth day) from login, not tied to browser.
LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "submissions:submit"
LOGOUT_REDIRECT_URL = "submissions:submit"
# 16h — a single morning login on the booth laptops lasts a full booth day
# (>10h) without a mid-day re-login.
SESSION_COOKIE_AGE = 60 * 60 * 16
SESSION_EXPIRE_AT_BROWSER_CLOSE = False

# Cookie hardening — made explicit rather than relying on framework defaults.
# CSRF_COOKIE_HTTPONLY is safe here: the frontend reads the CSRF token from a
# hidden {% csrf_token %} form field, never from document.cookie.
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Lax"

LANGUAGE_CODE = "ko-kr"
TIME_ZONE = os.environ.get("DJANGO_TIME_ZONE", "Asia/Seoul")
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = os.environ.get("DJANGO_STATIC_ROOT", str(BASE_DIR / "staticfiles"))

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Sent on every response (dev and prod); cheap defense-in-depth.
SECURE_REFERRER_POLICY = "same-origin"

# Production hardening: active only when DEBUG is off (behind an nginx TLS proxy).
_csrf = os.environ.get("DJANGO_CSRF_TRUSTED_ORIGINS", "")
CSRF_TRUSTED_ORIGINS = [o.strip() for o in _csrf.split(",") if o.strip()]

if not DEBUG:
    # Fail closed: a production instance (DEBUG off) must not boot with the
    # dev-only secret key or without an explicit host allowlist. A missing env
    # var should stop the server, not silently downgrade its security.
    from django.core.exceptions import ImproperlyConfigured

    if SECRET_KEY == INSECURE_SECRET_KEY:
        raise ImproperlyConfigured(
            "DJANGO_SECRET_KEY must be set when DEBUG is off (production)."
        )
    if not ALLOWED_HOSTS:
        raise ImproperlyConfigured(
            "DJANGO_ALLOWED_HOSTS must be set when DEBUG is off (production)."
        )

    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SECURE_SSL_REDIRECT = os.environ.get("DJANGO_SECURE_SSL_REDIRECT", "1") not in ("0", "false", "")
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    # 1 year, satisfying HSTS preload requirements. includeSubDomains stays on.
    SECURE_HSTS_SECONDS = int(os.environ.get("DJANGO_HSTS_SECONDS", "31536000"))
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    # Preload is a semi-irreversible commitment (every subdomain must be HTTPS),
    # so it is staged but opt-in: set DJANGO_HSTS_PRELOAD=1 once you are sure.
    SECURE_HSTS_PRELOAD = os.environ.get("DJANGO_HSTS_PRELOAD", "0") not in ("0", "false", "False", "")

elif SECRET_KEY != INSECURE_SECRET_KEY:
    # A real secret key is configured but DEBUG is still on — almost certainly a
    # production host that forgot DJANGO_DEBUG=0. Refuse rather than fail open.
    from django.core.exceptions import ImproperlyConfigured

    raise ImproperlyConfigured(
        "DJANGO_DEBUG must be 0 in production (a real DJANGO_SECRET_KEY is set "
        "but DEBUG is on)."
    )

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[{asctime}] {levelname} {name}: {message}",
            "style": "{",
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        }
    },
    "loggers": {
        "submissions.orchestrator": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        }
    },
}
