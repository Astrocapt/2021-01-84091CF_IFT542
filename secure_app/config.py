"""
secure_app/config.py
====================
Configuration. Addresses the "security misconfiguration" requirement of Task 3.

Rules applied:
  * No secret has a usable hardcoded default in production mode. SECRET_KEY is
    read from the environment; if it is absent the application refuses to start
    in production rather than silently falling back to a guessable value.
  * Debug is off by default. It is enabled only by an explicit environment
    variable, because Flask's debugger exposes an interactive console.
  * There are no default administrative credentials. The seed script generates
    a random password and prints it once to the operator's terminal.
  * Cookie flags are set centrally so no individual view can weaken them.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class BaseConfig:
    # --- session cookie hardening -----------------------------------------
    SESSION_COOKIE_NAME = "sr_session"
    SESSION_COOKIE_HTTPONLY = True     # not readable from document.cookie
    SESSION_COOKIE_SAMESITE = "Lax"    # withheld on cross-site POST (anti-CSRF layer 2)
    SESSION_COOKIE_SECURE = True       # TLS only; relaxed in the lab profile below
    PERMANENT_SESSION_LIFETIME = 1800  # 30-minute idle ceiling
    SESSION_REFRESH_EACH_REQUEST = False

    # --- uploads -----------------------------------------------------------
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024          # 2 MiB hard request cap
    UPLOAD_DIR = BASE_DIR / "instance" / "uploads"  # outside any served path
    ALLOWED_UPLOAD_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg"}
    ALLOWED_UPLOAD_MIMETYPES = {
        "application/pdf", "image/png", "image/jpeg",
    }

    # --- data --------------------------------------------------------------
    DATABASE = str(BASE_DIR / "instance" / "registration.sqlite3")
    AUDIT_LOG = str(BASE_DIR / "evidence" / "logs" / "security.log")

    # --- outbound fetch policy (SSRF) --------------------------------------
    URL_PREVIEW_ALLOWLIST = {
        "registry.futminna.test",
        "docs.futminna.test",
        "example.org",
    }
    URL_PREVIEW_TIMEOUT = 4
    URL_PREVIEW_MAX_BYTES = 65536

    DEBUG = False
    TESTING = False
    PROPAGATE_EXCEPTIONS = False


class LabConfig(BaseConfig):
    """
    Localhost teaching profile. The ONLY relaxation is the Secure cookie flag,
    because the lab origin is plain HTTP on 127.0.0.1 and a Secure cookie would
    never be sent. Every other control stays on.
    """
    SESSION_COOKIE_SECURE = False
    ENV_NAME = "lab"


class TestConfig(BaseConfig):
    TESTING = True
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = True
    ENV_NAME = "test"


class ProductionConfig(BaseConfig):
    ENV_NAME = "production"


def load_config(app, profile: str | None = None) -> None:
    profile = (profile or os.environ.get("APP_PROFILE") or "lab").lower()
    app.config.from_object(
        {"lab": LabConfig, "test": TestConfig, "production": ProductionConfig}[profile]
    )

    secret = os.environ.get("SECRET_KEY")
    if not secret:
        if profile == "production":
            raise RuntimeError(
                "SECRET_KEY is not set. Refusing to start in production with a "
                "default signing key."
            )
        # Ephemeral per-process key for lab/test. Sessions do not survive a
        # restart, which is acceptable locally and is safer than a constant.
        secret = os.urandom(32).hex()
    app.config["SECRET_KEY"] = secret

    if os.environ.get("FLASK_DEBUG") == "1" and profile != "production":
        app.config["DEBUG"] = True

    # Allow the test-suite to point at a scratch database.
    if os.environ.get("DATABASE_PATH"):
        app.config["DATABASE"] = os.environ["DATABASE_PATH"]
    if os.environ.get("AUDIT_LOG_PATH"):
        app.config["AUDIT_LOG"] = os.environ["AUDIT_LOG_PATH"]
