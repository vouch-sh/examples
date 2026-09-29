import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
# No fallback: a default key baked into the source lets anyone forge sessions for
# every deployment that forgot to set one. Left empty, Django refuses to use it
# (ImproperlyConfigured) while still allowing the build-time `migrate`.
SECRET_KEY = os.environ.get("SECRET_KEY", "")
# Off unless asked for: debug pages expose settings and stack traces.
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
# Comma-separated. The default is what Django itself allows in development.
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", ".localhost,127.0.0.1,[::1]").split(",")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "allauth.socialaccount.providers.openid_connect",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "allauth.account.middleware.AccountMiddleware",
]

ROOT_URLCONF = "urls"
WSGI_APPLICATION = "wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

SITE_ID = 1

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
]

SOCIALACCOUNT_PROVIDERS = {
    "openid_connect": {
        "APPS": [
            {
                "provider_id": "vouch",
                "name": "Vouch",
                "client_id": os.environ.get("VOUCH_CLIENT_ID", ""),
                "secret": os.environ.get("VOUCH_CLIENT_SECRET", ""),
                "settings": {
                    "server_url": os.environ.get("VOUCH_ISSUER", "https://us.vouch.sh"),
                    "fetch_userinfo": True,
                    "oauth_pkce_enabled": True,
                },
            }
        ],
    },
}

ACCOUNT_ADAPTER = "adapters.VouchAccountAdapter"

LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/"
STATIC_URL = "static/"
