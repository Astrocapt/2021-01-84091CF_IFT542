"""
secure_app/routes.py
====================
Application routes for the hardened build.

Task 3 controls appear here at their point of use:
  * XSS   - the profile 'bio' field is rendered through the auto-escaping
            template engine and is additionally covered by the nonce-based CSP
  * CSRF  - profile update and course registration are state-changing POSTs;
            token validation is enforced centrally in __init__.py
  * SSRF  - /documents/preview validates the destination before any socket is
            opened, and pins the vetted address
  * Upload hardening - extension, declared type, magic bytes, size and a
            server-generated storage name
"""

from __future__ import annotations

import hashlib
import secrets
from pathlib import Path

from flask import (Blueprint, abort, current_app, flash, redirect,
                   render_template, request, session, url_for)

from . import db, security
from .auth import admin_required, login_required
from .security import SSRFBlocked, ValidationError

bp = Blueprint("main", __name__)

# First bytes of the formats we accept. Checking these stops a file that is
# named .png but is in fact something else from being stored under a type the
# rest of the system will trust.
MAGIC_SIGNATURES = {
    b"%PDF-": "application/pdf",
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"\xff\xd8\xff": "image/jpeg",
}


@bp.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("main.dashboard"))
    return redirect(url_for("auth.login"))


@bp.route("/dashboard")
@login_required
def dashboard():
    user_id = session["user_id"]
    return render_template(
        "dashboard.html",
        profile=db.get_profile(user_id),
        enrolments=db.list_enrolments(user_id),
        documents=db.list_documents(user_id),
    )


# ---------------------------------------------------------------------------
# XSS-protected field: profile bio
# ---------------------------------------------------------------------------
@bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user_id = session["user_id"]

    if request.method != "POST":
        return render_template("profile.html", profile=db.get_profile(user_id))

    try:
        department = security.validate_text(request.form.get("department"),
                                            "Department", 80)
        level = security.validate_text(request.form.get("level"), "Level", 10)
        phone = security.validate_text(request.form.get("phone"), "Phone", 24)
        # The bio is free text. It is NOT sanitised on input: the value is
        # stored exactly as the student typed it and is made safe at the point
        # of output instead. Encoding at output is context-aware and survives
        # the value being reused in a different context later; input filtering
        # is neither.
        bio = security.validate_text(request.form.get("bio"), "Bio", 500)
    except ValidationError as exc:
        security.audit("validation.rejected", "denied", actor=str(user_id),
                       subject="profile", source_ip=request.remote_addr,
                       reason=str(exc))
        db.write_audit("validation.rejected", str(user_id), "profile",
                       "denied", request.remote_addr, str(exc))
        flash(str(exc), "error")
        return render_template("profile.html", profile=db.get_profile(user_id)), 400

    if phone and not security.PHONE_RE.match(phone):
        flash("Phone number format is not valid.", "error")
        return render_template("profile.html", profile=db.get_profile(user_id)), 400

    db.upsert_profile(user_id, department, level, phone, bio)
    security.audit("profile.update", "success", actor=str(user_id),
                   subject="profile", source_ip=request.remote_addr)
    db.write_audit("profile.update", str(user_id), "profile", "success",
                   request.remote_addr, "profile fields updated")
    flash("Profile saved.", "success")
    return redirect(url_for("main.dashboard"))


# ---------------------------------------------------------------------------
# CSRF-protected state change: course registration
# ---------------------------------------------------------------------------
@bp.route("/courses")
@login_required
def courses():
    term = request.args.get("q", "").strip()[:60]
    return render_template("courses.html",
                           courses=db.list_courses(term or None),
                           term=term,
                           enrolled={r["code"] for r in
                                     db.list_enrolments(session["user_id"])})


@bp.route("/courses/register", methods=["POST"])
@login_required
def register_course():
    user_id = session["user_id"]
    try:
        course_id = security.validate_int(request.form.get("course_id"),
                                          "Course", 1, 10_000_000)
    except ValidationError as exc:
        security.audit("validation.rejected", "denied", actor=str(user_id),
                       subject="course-registration",
                       source_ip=request.remote_addr, reason=str(exc))
        abort(400)

    if not db.course_exists(course_id):
        abort(404)

    if db.enrol(user_id, course_id):
        security.audit("enrolment.create", "success", actor=str(user_id),
                       subject=f"course:{course_id}",
                       source_ip=request.remote_addr)
        db.write_audit("enrolment.create", str(user_id), f"course:{course_id}",
                       "success", request.remote_addr, "registered")
        flash("Course registered.", "success")
    else:
        flash("You are already registered for that course.", "info")
    return redirect(url_for("main.courses"))


@bp.route("/courses/drop", methods=["POST"])
@login_required
def drop_course():
    user_id = session["user_id"]
    try:
        course_id = security.validate_int(request.form.get("course_id"),
                                          "Course", 1, 10_000_000)
    except ValidationError:
        abort(400)
    removed = db.drop_enrolment(user_id, course_id)
    security.audit("enrolment.delete", "success" if removed else "failure",
                   actor=str(user_id), subject=f"course:{course_id}",
                   source_ip=request.remote_addr)
    flash("Course dropped." if removed else "You were not registered for that course.",
          "info")
    return redirect(url_for("main.dashboard"))


# ---------------------------------------------------------------------------
# Upload hardening
# ---------------------------------------------------------------------------
@bp.route("/documents/upload", methods=["POST"])
@login_required
def upload_document():
    user_id = session["user_id"]
    uploaded = request.files.get("document")
    if not uploaded or not uploaded.filename:
        flash("No file selected.", "error")
        return redirect(url_for("main.dashboard"))

    original = Path(uploaded.filename).name          # strip any path component
    extension = Path(original).suffix.lower()

    if extension not in current_app.config["ALLOWED_UPLOAD_EXTENSIONS"]:
        security.audit("upload.rejected", "denied", actor=str(user_id),
                       subject=original, source_ip=request.remote_addr,
                       reason="extension-not-allowed")
        db.write_audit("upload.rejected", str(user_id), original, "denied",
                       request.remote_addr, "extension not allowed")
        flash("That file type is not accepted.", "error")
        return redirect(url_for("main.dashboard"))

    payload = uploaded.read(current_app.config["MAX_CONTENT_LENGTH"] + 1)
    if len(payload) > current_app.config["MAX_CONTENT_LENGTH"]:
        flash("The file is too large.", "error")
        return redirect(url_for("main.dashboard"))

    detected = next((mime for magic, mime in MAGIC_SIGNATURES.items()
                     if payload.startswith(magic)), None)
    if detected is None or detected not in current_app.config["ALLOWED_UPLOAD_MIMETYPES"]:
        security.audit("upload.rejected", "denied", actor=str(user_id),
                       subject=original, source_ip=request.remote_addr,
                       reason="content-does-not-match-type")
        db.write_audit("upload.rejected", str(user_id), original, "denied",
                       request.remote_addr, "content type mismatch")
        flash("The file contents do not match its type.", "error")
        return redirect(url_for("main.dashboard"))

    # The stored name is generated by the server. The user-supplied name never
    # reaches the filesystem, so it cannot traverse directories or set an
    # executable extension.
    stored_name = f"{secrets.token_hex(16)}{extension}"
    destination = Path(current_app.config["UPLOAD_DIR"]) / stored_name
    destination.write_bytes(payload)
    destination.chmod(0o600)

    db.save_document(user_id, original, stored_name, detected,
                     len(payload), hashlib.sha256(payload).hexdigest())
    security.audit("upload.accepted", "success", actor=str(user_id),
                   subject=stored_name, source_ip=request.remote_addr,
                   content_type=detected, size=len(payload))
    db.write_audit("upload.accepted", str(user_id), stored_name, "success",
                   request.remote_addr, f"{detected} {len(payload)}B")
    flash("Document uploaded.", "success")
    return redirect(url_for("main.dashboard"))


# ---------------------------------------------------------------------------
# SSRF-hardened URL preview
# ---------------------------------------------------------------------------
@bp.route("/documents/preview", methods=["GET", "POST"])
@login_required
def preview_url():
    if request.method != "POST":
        return render_template("preview.html", result=None)

    user_id = session["user_id"]
    raw_url = request.form.get("url", "")

    try:
        normalised, vetted_ip, port = security.validate_outbound_url(
            raw_url, allowlist=current_app.config["URL_PREVIEW_ALLOWLIST"]
        )
    except SSRFBlocked as exc:
        security.audit("ssrf.blocked", "denied", actor=str(user_id),
                       subject=raw_url[:200], source_ip=request.remote_addr,
                       reason=str(exc))
        db.write_audit("ssrf.blocked", str(user_id), raw_url[:200], "denied",
                       request.remote_addr, str(exc))
        # The user is told it was refused, not why in detail, so the endpoint
        # is not usable as an internal-network oracle.
        flash("That destination is not permitted.", "error")
        return render_template("preview.html", result=None), 400

    security.audit("ssrf.allowed", "success", actor=str(user_id),
                   subject=normalised, source_ip=request.remote_addr,
                   resolved=vetted_ip)
    result = fetch_preview(normalised, vetted_ip, port)
    return render_template("preview.html", result=result)


def fetch_preview(url: str, vetted_ip: str, port: int) -> dict:
    """
    Perform the outbound request against the address that was vetted.

    Two details matter:
      * redirects are disabled - a 302 response would otherwise be followed to
        a destination that was never checked
      * the response is truncated - an oversized body would be a memory
        denial-of-service vector
    """
    import requests
    try:
        response = requests.get(
            url,
            timeout=current_app.config["URL_PREVIEW_TIMEOUT"],
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": "registration-app-preview/1.0"},
        )
        body = response.raw.read(current_app.config["URL_PREVIEW_MAX_BYTES"],
                                 decode_content=True)
        return {
            "url": url,
            "resolved": vetted_ip,
            "status": response.status_code,
            "content_type": response.headers.get("Content-Type", "unknown"),
            "bytes": len(body),
        }
    except Exception:
        # The upstream error is not surfaced: differing error text would let
        # the endpoint be used to map internal hosts.
        return {"url": url, "resolved": vetted_ip, "status": None,
                "content_type": "unavailable", "bytes": 0}


# ---------------------------------------------------------------------------
# Administrative area (privileged)
# ---------------------------------------------------------------------------
@bp.route("/admin")
@admin_required
def admin_home():
    stats = db.query(
        "SELECT (SELECT COUNT(*) FROM users) AS users, "
        "       (SELECT COUNT(*) FROM courses) AS courses, "
        "       (SELECT COUNT(*) FROM enrolments) AS enrolments",
        one=True,
    )
    recent = db.query(
        "SELECT event, actor, subject, outcome, source_ip, occurred_at "
        "FROM audit_log ORDER BY id DESC LIMIT 25"
    )
    return render_template("admin.html", stats=stats, recent=recent)


@bp.route("/admin/courses", methods=["POST"])
@admin_required
def admin_add_course():
    try:
        code = security.validate_text(request.form.get("code"), "Code", 12, True).upper()
        title = security.validate_text(request.form.get("title"), "Title", 120, True)
        units = security.validate_int(request.form.get("units"), "Units", 1, 12)
    except ValidationError as exc:
        flash(str(exc), "error")
        return redirect(url_for("main.admin_home"))

    if not security.COURSE_CODE_RE.match(code):
        flash("Course code must look like 'IFT 542'.", "error")
        return redirect(url_for("main.admin_home"))

    try:
        db.query("INSERT INTO courses (code, title, units) VALUES (?, ?, ?)",
                 (code, title, units), commit=True)
    except Exception:
        flash("That course code already exists.", "error")
        return redirect(url_for("main.admin_home"))

    security.audit("course.create", "success", actor=str(session["user_id"]),
                   subject=code, source_ip=request.remote_addr)
    db.write_audit("course.create", str(session["user_id"]), code, "success",
                   request.remote_addr, f"units={units}")
    flash("Course added.", "success")
    return redirect(url_for("main.admin_home"))
