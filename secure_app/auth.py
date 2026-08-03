"""
secure_app/auth.py
==================
Authentication and session management - the "after" state for Task 2.

Corrects the three defects preserved in insecure_baseline/legacy_login.py:

    D1  string-built SQL   ->  parameterised lookup by identifier only
    D2  plaintext password ->  Argon2id hash + library verification
    D3  verbose errors     ->  one generic message for every failure mode

and adds four supplementary controls:

    C1  per-account temporary lockout
    C2  per-source-IP rate limiting
    C3  TOTP multi-factor for the privileged (admin) role
    C4  session identifier regeneration on privilege change
"""

from __future__ import annotations

import functools
import secrets

from flask import (Blueprint, abort, flash, redirect, render_template,
                   request, session, url_for)

from . import db, security
from .security import ValidationError

bp = Blueprint("auth", __name__)

# One message for every failure. Whether the account does not exist, the
# password is wrong, or the account is locked, the client is told the same
# thing, so the response cannot be used to enumerate valid accounts.
GENERIC_LOGIN_ERROR = "Invalid credentials. Please check your details and try again."


# ---------------------------------------------------------------------------
# Access-control decorators
# ---------------------------------------------------------------------------
def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            security.audit("authz.denied", "denied", subject=request.path,
                           source_ip=request.remote_addr, reason="not-authenticated")
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("auth.login"))
        # Authorisation is decided from the server-side record of the role,
        # never from a form field, header or hidden input.
        if session.get("role") != "admin":
            security.audit("authz.denied", "denied",
                           actor=str(session.get("user_id")),
                           subject=request.path,
                           source_ip=request.remote_addr,
                           reason="insufficient-role")
            db.write_audit("authz.denied", str(session.get("user_id")),
                           request.path, "denied", request.remote_addr,
                           "role=student attempted admin route")
            abort(403)
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# C4: session identifier regeneration
# ---------------------------------------------------------------------------
def regenerate_session(preserve: dict | None = None) -> None:
    """
    Discard all pre-authentication session state and mint a new session
    identifier and CSRF token.

    Flask signs its session into a cookie rather than keeping a server-side
    store, so there is no server record to renumber. The equivalent fixation
    control is to clear the session dictionary completely and issue a new
    identifier claim, which invalidates any value an attacker planted in the
    victim's session before login (session fixation, CWE-384) and prevents the
    pre-auth CSRF token from carrying over into the authenticated session.
    """
    session.clear()
    session["sid"] = secrets.token_urlsafe(24)
    session[security.CSRF_SESSION_KEY] = security.new_csrf_token()
    session.permanent = True
    for key, value in (preserve or {}).items():
        session[key] = value


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------
@bp.route("/login", methods=["GET", "POST"])
def login():
    # Anything that is not a POST (GET, HEAD) renders the form. Testing for
    # != "POST" rather than == "GET" matters: a HEAD request would otherwise
    # fall through into the credential-processing branch.
    if request.method != "POST":
        return render_template("login.html")

    source_ip = request.remote_addr or "unknown"

    # --- input validation before anything touches the data layer ----------
    try:
        email = security.validate_email(request.form.get("email"))
        password = security.validate_password(request.form.get("password"))
    except ValidationError:
        # The specific rule that failed is not disclosed at the login screen.
        security.audit("auth.login", "failure", subject="login",
                       source_ip=source_ip, email=request.form.get("email", ""),
                       reason="validation-failed")
        flash(GENERIC_LOGIN_ERROR, "error")
        return render_template("login.html"), 401

    # --- C2: per-source rate limit ----------------------------------------
    recent_ip_failures = db.count_recent_failures_for_ip(
        source_ip, security.window_start(security.IP_WINDOW_MINUTES)
    )
    if recent_ip_failures >= security.MAX_IP_FAILURES:
        security.audit("auth.ratelimit", "denied", subject="login",
                       source_ip=source_ip, email=email,
                       failures_in_window=recent_ip_failures)
        db.write_audit("auth.ratelimit", "anonymous", "login", "denied",
                       source_ip, f"{recent_ip_failures} failures in window")
        flash("Too many attempts from this location. Try again later.", "error")
        return render_template("login.html"), 429

    # --- D1 corrected: retrieve the account by IDENTIFIER ONLY ------------
    # The password is not part of the query. It is verified afterwards, in
    # application code, against the stored hash.
    user = db.find_user_by_email(email)

    # --- C1: account lockout check ----------------------------------------
    if user and security.is_locked(user["locked_until"]):
        db.record_login_attempt(email, source_ip, False)
        security.audit("auth.login", "denied", actor=str(user["id"]),
                       subject="login", source_ip=source_ip, email=email,
                       reason="account-locked")
        db.write_audit("auth.login", str(user["id"]), "login", "denied",
                       source_ip, "account temporarily locked")
        flash(GENERIC_LOGIN_ERROR, "error")   # same message as any other failure
        return render_template("login.html"), 401

    # --- D2 corrected: verify against the Argon2id hash -------------------
    stored = user["password_hash"] if user else None
    if not security.verify_password(stored, password):
        db.record_login_attempt(email, source_ip, False)
        if user:
            attempts = user["failed_attempts"] + 1
            locked = (security.lock_expiry()
                      if attempts >= security.MAX_ACCOUNT_FAILURES else None)
            db.set_failed_attempts(user["id"], attempts, locked)
            if locked:
                security.audit("auth.lockout", "denied", actor=str(user["id"]),
                               subject="login", source_ip=source_ip, email=email,
                               attempts=attempts)
                db.write_audit("auth.lockout", str(user["id"]), "login",
                               "denied", source_ip,
                               f"locked after {attempts} failures")
        security.audit("auth.login", "failure",
                       actor=str(user["id"]) if user else "anonymous",
                       subject="login", source_ip=source_ip, email=email,
                       reason="bad-credentials")
        db.write_audit("auth.login", str(user["id"]) if user else "anonymous",
                       "login", "failure", source_ip, "invalid credentials")
        flash(GENERIC_LOGIN_ERROR, "error")
        return render_template("login.html"), 401

    # --- transparent hash upgrade ----------------------------------------
    if security.needs_rehash(stored):
        db.update_password_hash(user["id"], security.hash_password(password))

    db.record_login_attempt(email, source_ip, True)
    db.clear_lockout(user["id"])

    # --- C3: MFA for privileged accounts ----------------------------------
    if user["role"] == "admin" and user["mfa_enabled"]:
        regenerate_session({"pending_mfa_user": user["id"]})
        security.audit("auth.mfa_challenge", "success", actor=str(user["id"]),
                       subject="login", source_ip=source_ip, email=email)
        return redirect(url_for("auth.mfa"))

    _establish_session(user, source_ip)
    return redirect(url_for("main.dashboard"))


def _establish_session(user, source_ip: str) -> None:
    """C4: a fully new session is minted at the moment privilege changes."""
    regenerate_session({
        "user_id": user["id"],
        "user_email": user["email"],
        "role": user["role"],
        "full_name": user["full_name"],
    })
    security.audit("auth.login", "success", actor=str(user["id"]),
                   subject="login", source_ip=source_ip, email=user["email"],
                   role=user["role"])
    db.write_audit("auth.login", str(user["id"]), "login", "success",
                   source_ip, f"role={user['role']}")


# ---------------------------------------------------------------------------
# MFA step
# ---------------------------------------------------------------------------
@bp.route("/login/mfa", methods=["GET", "POST"])
def mfa():
    pending = session.get("pending_mfa_user")
    if not pending:
        return redirect(url_for("auth.login"))

    if request.method != "POST":
        return render_template("mfa.html")

    source_ip = request.remote_addr or "unknown"
    row = db.query(
        "SELECT id, email, full_name, role, mfa_secret FROM users WHERE id = ?",
        (pending,), one=True,
    )
    submitted = request.form.get("code", "")

    if not row or not security.verify_totp(row["mfa_secret"], submitted):
        security.audit("auth.mfa", "failure", actor=str(pending),
                       subject="login", source_ip=source_ip, otp=submitted)
        db.write_audit("auth.mfa", str(pending), "login", "failure",
                       source_ip, "invalid second factor")
        flash("Invalid verification code.", "error")
        return render_template("mfa.html"), 401

    security.audit("auth.mfa", "success", actor=str(row["id"]),
                   subject="login", source_ip=source_ip)
    _establish_session(row, source_ip)
    return redirect(url_for("main.dashboard"))


# ---------------------------------------------------------------------------
# Logout and password change
# ---------------------------------------------------------------------------
@bp.route("/logout", methods=["POST"])
def logout():
    actor = str(session.get("user_id", "anonymous"))
    security.audit("auth.logout", "success", actor=actor,
                   source_ip=request.remote_addr)
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method != "POST":
        return render_template("password.html")

    source_ip = request.remote_addr or "unknown"
    user = db.find_user_by_email(session["user_email"])
    current = request.form.get("current_password", "")
    try:
        new_password = security.validate_password(request.form.get("new_password"))
    except ValidationError as exc:
        flash(str(exc), "error")
        return render_template("password.html"), 400

    if request.form.get("new_password") != request.form.get("confirm_password"):
        flash("The new passwords do not match.", "error")
        return render_template("password.html"), 400

    if not security.verify_password(user["password_hash"], current):
        security.audit("auth.password_change", "failure",
                       actor=str(user["id"]), source_ip=source_ip,
                       reason="current-password-incorrect")
        flash("Current password is incorrect.", "error")
        return render_template("password.html"), 401

    db.update_password_hash(user["id"], security.hash_password(new_password))
    security.audit("auth.password_change", "success", actor=str(user["id"]),
                   source_ip=source_ip)
    db.write_audit("auth.password_change", str(user["id"]), "account",
                   "success", source_ip, "password rotated")

    # Re-establish the session so an old cookie cannot outlive the credential.
    regenerate_session({
        "user_id": user["id"], "user_email": user["email"],
        "role": user["role"], "full_name": user["full_name"],
    })
    flash("Password updated.", "success")
    return redirect(url_for("main.dashboard"))
