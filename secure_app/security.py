"""
secure_app/security.py
======================
Central security services for the hardened Student Registration application.

Every control required by Tasks 2 and 3 of the IFT 542 practical assignment is
implemented here so that the controls are auditable in one place rather than
scattered through request handlers.

Contents
--------
1. Password hashing (Argon2id)          - Task 2
2. Input validation                     - Task 2
3. Rate limiting and account lockout    - Task 2
4. TOTP multi-factor for privileged     - Task 2
5. Anti-CSRF tokens                     - Task 3
6. SSRF destination guard               - Task 3
7. Security headers / CSP               - Task 3
8. Redacted security audit logging      - Task 3
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import struct
import time
from datetime import datetime, timedelta, timezone
from typing import Iterable
from urllib.parse import urlparse

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError, VerificationError

# ===========================================================================
# 1. PASSWORD HASHING  (Argon2id)
# ===========================================================================
# Argon2id was the Password Hashing Competition winner and is the first
# recommendation of the OWASP Password Storage Cheat Sheet. It is memory-hard,
# which raises the cost of GPU/ASIC-assisted offline cracking in a way that
# iteration-only functions such as PBKDF2 do not. Parameters below follow the
# OWASP baseline of 19 MiB memory, 2 iterations, 1 degree of parallelism.
#
# A salt is generated per password by the library and embedded in the encoded
# hash string, so two identical passwords never produce identical stored
# values and precomputed rainbow tables do not apply.

_hasher = PasswordHasher(
    time_cost=2,          # iterations
    memory_cost=19456,    # 19 MiB
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID,         # Argon2id: hybrid of Argon2i and Argon2d
)

# Pre-computed hash of a value no account uses. Verifying against this when the
# email does not exist keeps the response time of "unknown user" close to that
# of "known user, wrong password", denying an attacker a timing oracle for
# username enumeration.
_DUMMY_HASH = _hasher.hash("not-a-real-password-" + secrets.token_hex(8))


def hash_password(plaintext: str) -> str:
    """Return an Argon2id encoded hash: $argon2id$v=19$m=...,t=...,p=...$salt$digest"""
    return _hasher.hash(plaintext)


def verify_password(stored_hash: str | None, candidate: str) -> bool:
    """
    Constant-ish time password verification.

    Always performs a full Argon2 verification even when the account does not
    exist, so that timing does not disclose account existence.
    """
    if not stored_hash:
        try:
            _hasher.verify(_DUMMY_HASH, candidate)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            pass
        return False
    try:
        return _hasher.verify(stored_hash, candidate)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True when the stored hash used weaker parameters than current policy."""
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


# ===========================================================================
# 2. INPUT VALIDATION
# ===========================================================================
# Validation is defence in depth, not the primary SQL-injection control.
# Parameterisation (see secure_app/db.py) is the primary control; validation
# additionally rejects input that is the wrong type, length or shape before it
# reaches business logic.

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}$")
MATRIC_RE = re.compile(r"^[0-9]{4}[/-][0-9]{2}[/-][0-9A-Za-z]{3,12}$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9 \-]{6,19}$")
COURSE_CODE_RE = re.compile(r"^[A-Z]{2,4}[ ]?[0-9]{3}$")

MAX_EMAIL_LEN = 254        # RFC 5321 maximum
MIN_PASSWORD_LEN = 12
MAX_PASSWORD_LEN = 128     # bounded to prevent hashing-cost denial of service


class ValidationError(ValueError):
    """Raised when user-supplied input fails a validation rule."""


def validate_email(value: str | None) -> str:
    if not isinstance(value, str):
        raise ValidationError("Email must be text.")
    value = value.strip().lower()
    if not value or len(value) > MAX_EMAIL_LEN:
        raise ValidationError("Email is missing or too long.")
    if not EMAIL_RE.match(value):
        raise ValidationError("Email format is not valid.")
    return value


def validate_password(value: str | None) -> str:
    if not isinstance(value, str):
        raise ValidationError("Password must be text.")
    if not (MIN_PASSWORD_LEN <= len(value) <= MAX_PASSWORD_LEN):
        raise ValidationError(
            f"Password must be between {MIN_PASSWORD_LEN} and {MAX_PASSWORD_LEN} characters."
        )
    return value


def validate_matric(value: str | None) -> str:
    if not isinstance(value, str) or not MATRIC_RE.match(value.strip()):
        raise ValidationError("Matriculation number format is not valid.")
    return value.strip().upper()


def validate_text(value: str | None, field: str, max_len: int, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be text.")
    value = value.strip()
    if required and not value:
        raise ValidationError(f"{field} is required.")
    if len(value) > max_len:
        raise ValidationError(f"{field} exceeds {max_len} characters.")
    return value


def validate_int(value, field: str, low: int, high: int) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValidationError(f"{field} must be a whole number.")
    if not (low <= parsed <= high):
        raise ValidationError(f"{field} is out of the accepted range.")
    return parsed


# ===========================================================================
# 3. RATE LIMITING AND TEMPORARY ACCOUNT LOCKOUT
# ===========================================================================
# Two independent counters are enforced:
#   * per-account : slows credential stuffing against one victim
#   * per-source  : slows password spraying across many accounts from one host
# Lockout is temporary (not permanent) so that an attacker cannot use it to
# deny service to a legitimate student indefinitely.

MAX_ACCOUNT_FAILURES = 5
ACCOUNT_LOCK_MINUTES = 15
MAX_IP_FAILURES = 20
IP_WINDOW_MINUTES = 15


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def lock_expiry() -> str:
    return iso(utc_now() + timedelta(minutes=ACCOUNT_LOCK_MINUTES))


def is_locked(locked_until: str | None) -> bool:
    expiry = parse_iso(locked_until)
    return bool(expiry and expiry > utc_now())


# SQLite stores datetime('now') as 'YYYY-MM-DD HH:MM:SS' in UTC. Timestamps
# that are compared inside the database must be written in exactly that
# format, otherwise the lexical comparison used for the rate-limit window
# silently never matches. ISO-8601 with a 'T' separator and an offset is kept
# for values that are only ever parsed back in Python (for example
# users.locked_until).
SQL_TS_FORMAT = "%Y-%m-%d %H:%M:%S"


def sql_now() -> str:
    return utc_now().strftime(SQL_TS_FORMAT)


def sql_window(minutes_ago: int) -> str:
    """Timestamp `minutes_ago` minutes in the past, in SQLite's text format.
    A negative argument returns a point in the future (used by tests)."""
    return (utc_now() - timedelta(minutes=minutes_ago)).strftime(SQL_TS_FORMAT)


def window_start(minutes: int) -> str:
    return sql_window(minutes)


# ===========================================================================
# 4. TOTP MULTI-FACTOR AUTHENTICATION (privileged accounts)
# ===========================================================================
# RFC 6238 time-based one-time passwords, implemented over the standard library
# so the project carries no additional dependency. Applied to the 'admin' role
# only, matching the assignment requirement of MFA for privileged accounts.

TOTP_STEP = 30
TOTP_DIGITS = 6
TOTP_DRIFT_STEPS = 1          # accept one step either side of current time


def generate_totp_secret() -> str:
    """Return a base32 secret suitable for an authenticator application."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_at(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


def current_totp(secret: str, at: float | None = None) -> str:
    return totp_at(secret, int((at or time.time()) // TOTP_STEP))


def verify_totp(secret: str | None, submitted: str | None, at: float | None = None) -> bool:
    """Verify a submitted OTP with a small drift window, in constant time."""
    if not secret or not submitted:
        return False
    submitted = submitted.strip().replace(" ", "")
    if not re.fullmatch(r"[0-9]{6}", submitted):
        return False
    counter = int((at or time.time()) // TOTP_STEP)
    ok = False
    for skew in range(-TOTP_DRIFT_STEPS, TOTP_DRIFT_STEPS + 1):
        # compare_digest on every branch: no early exit, no timing signal
        ok |= hmac.compare_digest(totp_at(secret, counter + skew), submitted)
    return ok


# ===========================================================================
# 5. ANTI-CSRF TOKENS
# ===========================================================================
# The synchroniser-token pattern. A random token is bound to the session and
# must be echoed in a hidden form field on every state-changing request. An
# attacker's page can cause a browser to send a cross-site POST, but the
# same-origin policy prevents it from reading the victim's token, so the
# forged request fails validation.
#
# SameSite=Lax on the session cookie is the second, independent layer: the
# browser withholds the cookie from cross-site POSTs entirely.

CSRF_FIELD = "csrf_token"
CSRF_SESSION_KEY = "_csrf_token"


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_is_valid(session_token: str | None, submitted: str | None) -> bool:
    if not session_token or not submitted:
        return False
    return hmac.compare_digest(str(session_token), str(submitted))


# ===========================================================================
# 6. SSRF DESTINATION GUARD
# ===========================================================================
# The URL-preview feature fetches a document reference on the user's behalf.
# Unrestricted, that turns the server into a proxy into the trusted network:
# the classic targets are the loopback interface, RFC 1918 ranges and cloud
# instance-metadata endpoints.
#
# Controls applied, in order:
#   a. scheme allowlist        - http/https only (no file:, gopher:, ftp:)
#   b. port allowlist          - 80/443 only
#   c. host allowlist          - explicit list of permitted destinations
#   d. DNS resolution + IP check - EVERY resolved address must be public
#   e. address pinning         - the caller connects to the vetted IP, closing
#                                the DNS-rebinding (TOCTOU) gap between the
#                                check and the connection
#   f. no automatic redirects  - a 302 to 169.254.169.254 would otherwise
#                                bypass every check above

ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443})

# Deliberately narrow. In the lab this list is the only way out of the app.
DEFAULT_HOST_ALLOWLIST = frozenset({
    "registry.futminna.test",
    "docs.futminna.test",
    "example.org",
})

BLOCKED_METADATA_IPS = frozenset({
    "169.254.169.254",   # AWS / Azure / DigitalOcean IMDS
    "100.100.100.100",   # Alibaba Cloud
    "192.0.0.192",       # Oracle Cloud
})


class SSRFBlocked(Exception):
    """Raised when a requested URL fails the destination policy."""


def _address_is_public(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        or ip.is_multicast or ip.is_unspecified
        or str(ip) in BLOCKED_METADATA_IPS
    )


def validate_outbound_url(
    raw_url: str,
    allowlist: Iterable[str] | None = None,
    resolver=None,
) -> tuple[str, str, int]:
    """
    Validate a user-supplied URL against the outbound destination policy.

    Returns (normalised_url, vetted_ip, port) on success.
    Raises SSRFBlocked with a non-leaking reason on failure.

    `resolver` is injectable so the test-suite can exercise the DNS branches
    without depending on live name resolution.
    """
    allow = frozenset(a.lower() for a in (allowlist if allowlist is not None
                                          else DEFAULT_HOST_ALLOWLIST))
    if not isinstance(raw_url, str) or len(raw_url) > 2048:
        raise SSRFBlocked("URL is missing or too long.")

    parsed = urlparse(raw_url.strip())

    # (a) scheme
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise SSRFBlocked("Only http and https destinations are permitted.")

    # Credentials in the authority are a common allowlist-bypass trick
    # (https://allowed.test@127.0.0.1/), so reject them outright.
    if parsed.username or parsed.password:
        raise SSRFBlocked("Credentials in the URL are not permitted.")

    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise SSRFBlocked("Destination host is missing.")

    # (b) port
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise SSRFBlocked("Destination port is not permitted.")

    # (c) host allowlist. Checked before resolution so that a blocked host is
    # rejected without the application making any network request at all.
    if host not in allow:
        raise SSRFBlocked("Destination host is not on the approved list.")

    # (d) resolve and vet every returned address
    resolve = resolver or _default_resolver
    try:
        addresses = resolve(host, port)
    except OSError:
        raise SSRFBlocked("Destination host could not be resolved.")
    if not addresses:
        raise SSRFBlocked("Destination host could not be resolved.")

    for addr in addresses:
        try:
            ip_obj = ipaddress.ip_address(addr)
        except ValueError:
            raise SSRFBlocked("Destination address is not valid.")
        if not _address_is_public(ip_obj):
            # One private answer condemns the whole name: a host that resolves
            # to both a public and an internal address is a rebinding attempt.
            raise SSRFBlocked("Destination resolves to a restricted network range.")

    # (e) pin the first vetted address for the actual connection
    vetted_ip = addresses[0]
    normalised = parsed.geturl()
    return normalised, vetted_ip, port


def _default_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    return [info[4][0] for info in infos]


# ===========================================================================
# 7. SECURITY HEADERS AND CONTENT SECURITY POLICY
# ===========================================================================
# The CSP is nonce-based rather than 'unsafe-inline'. Any script the attacker
# manages to inject lacks the per-response nonce and is therefore not executed,
# which is a second independent barrier behind output encoding.

def build_csp(nonce: str) -> str:
    return "; ".join([
        "default-src 'self'",
        f"script-src 'self' 'nonce-{nonce}'",
        f"style-src 'self' 'nonce-{nonce}'",
        "img-src 'self' data:",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "connect-src 'self'",
        "require-trusted-types-for 'script'",
    ])


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}

# Sent only over TLS. Setting HSTS on a plain-HTTP lab origin would be
# meaningless, so the application adds it conditionally (see __init__.py).
HSTS_HEADER = ("Strict-Transport-Security", "max-age=31536000; includeSubDomains")


def request_nonce() -> str:
    return secrets.token_urlsafe(16)


# ===========================================================================
# 8. SECURITY AUDIT LOGGING
# ===========================================================================
# Logs answer who / what / when / outcome and nothing more. Passwords, OTP
# codes, session identifiers and CSRF tokens are never written. Email addresses
# are masked because they are personal data that the log does not need in full
# to be useful for investigation.

SENSITIVE_KEYS = {
    "password", "pass", "pwd", "new_password", "confirm_password",
    "csrf_token", "session", "cookie", "authorization", "token",
    "otp", "mfa_code", "totp", "mfa_secret", "secret", "api_key",
}

_audit_logger: logging.Logger | None = None


def mask_email(email: str | None) -> str:
    """glory.abayomi@example.test -> g***i@example.test"""
    if not email or "@" not in email:
        return "unknown"
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked = local[0] + "*"
    else:
        masked = f"{local[0]}***{local[-1]}"
    return f"{masked}@{domain}"


def redact(payload: dict) -> dict:
    """Strip secret-bearing keys before anything is written to a log."""
    clean = {}
    for key, value in payload.items():
        if key.lower() in SENSITIVE_KEYS:
            clean[key] = "[REDACTED]"
        elif key.lower() in {"email", "username"}:
            clean[key] = mask_email(str(value))
        else:
            clean[key] = value
    return clean


def configure_audit_log(path: str) -> logging.Logger:
    """Attach a JSON-lines file handler for security events."""
    global _audit_logger
    os.makedirs(os.path.dirname(path), exist_ok=True)
    logger = logging.getLogger("ift542.security")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not any(isinstance(h, logging.FileHandler) and
               getattr(h, "baseFilename", "") == os.path.abspath(path)
               for h in logger.handlers):
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    _audit_logger = logger
    return logger


def audit(event: str, outcome: str, actor: str = "anonymous",
          subject: str | None = None, source_ip: str | None = None,
          **detail) -> dict:
    """
    Emit one structured security event.

    Returns the record so that callers (and tests) can assert on it.
    """
    record = {
        "ts": iso(utc_now()),
        "event": event,
        "outcome": outcome,
        "actor": actor,
        "subject": subject,
        "source_ip": source_ip,
        "detail": redact(detail),
    }
    if _audit_logger:
        _audit_logger.info(json.dumps(record, separators=(",", ":")))
    return record
