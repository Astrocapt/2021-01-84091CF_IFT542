"""
secure_app/__init__.py
======================
Application factory for the hardened Student Registration application.

Cross-cutting controls are installed here, once, so that they cannot be
forgotten by an individual view:

  * a per-response CSP nonce and the full security-header set
  * anti-CSRF enforcement on every state-changing method
  * generic error pages (no stack traces, no driver messages)
  * audit logging initialisation
"""

from __future__ import annotations

from flask import (Flask, abort, g, jsonify, render_template, request,
                   session)

from . import db, security
from .config import load_config


def create_app(profile: str | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=False)
    load_config(app, profile)

    security.configure_audit_log(app.config["AUDIT_LOG"])
    app.config["UPLOAD_DIR"].mkdir(parents=True, exist_ok=True)

    app.teardown_appcontext(db.close_db)

    # -- Jinja is left with autoescaping ON (the framework default). The
    #    application marks no user-controlled value as pre-escaped: there is no
    #    'safe' filter and no explicit escape-bypass anywhere in the templates
    #    or view code. tests/test_defences.py asserts this statically.
    app.jinja_env.autoescape = True

    # ------------------------------------------------------------------
    # Per-request setup: CSP nonce, CSRF token, session freshness
    # ------------------------------------------------------------------
    @app.before_request
    def _before():
        g.csp_nonce = security.request_nonce()

        if security.CSRF_SESSION_KEY not in session:
            session[security.CSRF_SESSION_KEY] = security.new_csrf_token()
        g.csrf_token = session[security.CSRF_SESSION_KEY]

        # ---- CSRF enforcement -----------------------------------------
        # Applied to every unsafe method, centrally. A view cannot opt out by
        # omission; it would have to be added to this exemption set explicitly.
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            submitted = (request.form.get(security.CSRF_FIELD)
                         or request.headers.get("X-CSRF-Token"))
            if not security.csrf_is_valid(g.csrf_token, submitted):
                security.audit(
                    "csrf.rejected", "denied",
                    actor=str(session.get("user_id", "anonymous")),
                    subject=request.path,
                    source_ip=request.remote_addr,
                    method=request.method,
                )
                abort(403)

    # ------------------------------------------------------------------
    # Per-response: security headers
    # ------------------------------------------------------------------
    @app.after_request
    def _headers(response):
        nonce = getattr(g, "csp_nonce", None)
        if nonce:
            response.headers["Content-Security-Policy"] = security.build_csp(nonce)
        for name, value in security.SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if request.is_secure:
            response.headers[security.HSTS_HEADER[0]] = security.HSTS_HEADER[1]
        # Drop any banner that would disclose the server stack. The value is
        # removed rather than replaced, because the WSGI layer beneath sets its
        # own and two assignments would otherwise both be emitted.
        response.headers.pop("Server", None)
        return response

    @app.context_processor
    def _inject():
        return {
            "csp_nonce": getattr(g, "csp_nonce", ""),
            "csrf_token": getattr(g, "csrf_token", ""),
            "csrf_field": security.CSRF_FIELD,
            "current_user": session.get("user_email"),
            "current_role": session.get("role"),
        }

    # ------------------------------------------------------------------
    # Generic error handling: never leak internals to the client
    # ------------------------------------------------------------------
    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def _client_error(err):
        code = getattr(err, "code", 400)
        messages = {
            400: "The request could not be processed.",
            403: "You are not permitted to perform this action.",
            404: "The requested page was not found.",
            413: "The uploaded file exceeds the permitted size.",
        }
        if request.accept_mimetypes.best == "application/json":
            return jsonify(error=messages.get(code, "Request rejected.")), code
        return render_template("error.html", code=code,
                               message=messages.get(code, "Request rejected.")), code

    @app.errorhandler(500)
    @app.errorhandler(Exception)
    def _server_error(err):
        # The detail goes to the server-side log; the client gets a reference
        # code only. This closes the CWE-209 verbose-error defect (D3) that the
        # legacy prototype had.
        import uuid
        ref = uuid.uuid4().hex[:12]
        app.logger.exception("unhandled error ref=%s", ref)
        security.audit("app.error", "failure", subject=request.path,
                       source_ip=request.remote_addr, ref=ref,
                       type=type(err).__name__)
        if request.accept_mimetypes.best == "application/json":
            return jsonify(error="Internal error.", reference=ref), 500
        return render_template("error.html", code=500,
                               message="An internal error occurred.",
                               reference=ref), 500

    # ------------------------------------------------------------------
    # Blueprints
    # ------------------------------------------------------------------
    from .auth import bp as auth_bp
    from .routes import bp as main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    @app.cli.command("init-db")
    def _init_db_cmd():
        db.init_db(app)
        print("Database initialised at", app.config["DATABASE"])

    return app
