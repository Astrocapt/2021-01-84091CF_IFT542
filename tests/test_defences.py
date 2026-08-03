"""
tests/test_defences.py
======================
Task 3 evidence: XSS, CSRF, SSRF, security misconfiguration and logging.

All SSRF tests use an injected resolver so that no name resolution or outbound
connection ever leaves the test process. Nothing outside localhost is touched.
"""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from secure_app import db as database, security                    # noqa: E402
from secure_app.security import SSRFBlocked                        # noqa: E402
from tests.conftest import (LAB_STUDENT, LAB_STUDENT_PASSWORD,     # noqa: E402
                            csrf_from)

# A benign marker string containing markup metacharacters. It is stored, then
# the rendered page is checked to confirm it comes back as text, not markup.
MARKUP_PROBE = '<script>marker</script>'
ATTRIBUTE_PROBE = '" onmouseover="marker'


# ===========================================================================
# XSS
# ===========================================================================
def test_stored_field_is_html_encoded_on_output(logged_in):
    token = csrf_from(logged_in, "/profile")
    logged_in.post("/profile", data={
        "department": "Information Technology", "level": "500",
        "phone": "+2348000000001", "bio": MARKUP_PROBE,
        "csrf_token": token}, follow_redirects=True)

    body = logged_in.get("/dashboard").get_data(as_text=True)
    # The raw markup does not appear ...
    assert MARKUP_PROBE not in body
    # ... the encoded form does, so the value renders as visible text.
    assert "&lt;script&gt;marker&lt;/script&gt;" in body


def test_attribute_context_probe_is_also_encoded(logged_in):
    token = csrf_from(logged_in, "/profile")
    logged_in.post("/profile", data={
        "department": ATTRIBUTE_PROBE, "level": "500", "phone": "",
        "bio": "", "csrf_token": token}, follow_redirects=True)
    body = logged_in.get("/profile").get_data(as_text=True)
    assert 'onmouseover="marker' not in body
    assert "&#34;" in body or "&quot;" in body


def test_value_is_stored_unmodified_and_made_safe_at_output(logged_in, app):
    """Encoding happens at output, not by mangling the stored data."""
    token = csrf_from(logged_in, "/profile")
    logged_in.post("/profile", data={
        "department": "IT", "level": "500", "phone": "",
        "bio": MARKUP_PROBE, "csrf_token": token}, follow_redirects=True)
    with app.app_context():
        assert database.get_profile(1)["bio"] == MARKUP_PROBE


def test_templates_contain_no_safe_filter_or_autoescape_disable():
    for template in (ROOT / "secure_app" / "templates").glob("*.html"):
        text = template.read_text(encoding="utf-8")
        assert "|safe" not in text, template.name
        assert "autoescape false" not in text, template.name
    for source in (ROOT / "secure_app").glob("*.py"):
        text = source.read_text(encoding="utf-8")
        assert "Markup(" not in text, source.name


def test_content_security_policy_is_restrictive(client):
    csp = client.get("/login").headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "base-uri 'none'" in csp
    # No blanket inline-script permission: injected script has no nonce.
    assert "'unsafe-inline'" not in csp
    assert "'unsafe-eval'" not in csp
    assert "nonce-" in csp


def test_csp_nonce_is_unique_per_response(client):
    first = client.get("/login").headers["Content-Security-Policy"]
    second = client.get("/login").headers["Content-Security-Policy"]
    assert first != second, "a reused nonce would be guessable across responses"


# ===========================================================================
# CSRF
# ===========================================================================
def test_state_change_without_a_token_is_rejected(logged_in):
    response = logged_in.post("/courses/register", data={"course_id": 1})
    assert response.status_code == 403


def test_state_change_with_a_wrong_token_is_rejected(logged_in):
    response = logged_in.post("/courses/register",
                              data={"course_id": 1,
                                    "csrf_token": "not-the-issued-token"})
    assert response.status_code == 403


def test_state_change_with_the_issued_token_succeeds(logged_in, app):
    token = csrf_from(logged_in, "/courses")
    response = logged_in.post("/courses/register",
                              data={"course_id": 1, "csrf_token": token})
    assert response.status_code == 302
    with app.app_context():
        assert len(database.list_enrolments(1)) == 1


def test_profile_update_is_csrf_protected(logged_in):
    assert logged_in.post("/profile", data={"bio": "no token"}).status_code == 403


def test_token_is_bound_to_the_session_not_shared_between_clients(app):
    a, b = app.test_client(), app.test_client()
    token_a = csrf_from(a)
    token_b = csrf_from(b)
    assert token_a != token_b
    # Client B's token must not authorise a request in client A's session.
    a.post("/login", data={"email": LAB_STUDENT,
                           "password": LAB_STUDENT_PASSWORD,
                           "csrf_token": token_a})
    assert a.post("/courses/register",
                  data={"course_id": 1, "csrf_token": token_b}).status_code == 403


def test_session_cookie_carries_samesite_and_httponly(client):
    token = csrf_from(client)
    response = client.post("/login", data={"email": LAB_STUDENT,
                                           "password": LAB_STUDENT_PASSWORD,
                                           "csrf_token": token})
    cookie = response.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_token_comparison_is_constant_time():
    assert security.csrf_is_valid("abc123", "abc123") is True
    assert security.csrf_is_valid("abc123", "abc124") is False
    assert security.csrf_is_valid(None, "abc123") is False
    assert security.csrf_is_valid("abc123", None) is False


# ===========================================================================
# SSRF
# ===========================================================================
def fake_resolver(mapping):
    def _resolve(host, port):
        if host not in mapping:
            raise OSError("name not resolved")
        return mapping[host]
    return _resolve


ALLOW = {"docs.futminna.test", "example.org"}
PUBLIC_MAP = {"docs.futminna.test": ["93.184.216.34"], "example.org": ["93.184.216.34"]}


def test_permitted_destination_is_accepted():
    url, ip, port = security.validate_outbound_url(
        "https://docs.futminna.test/handbook.pdf",
        allowlist=ALLOW, resolver=fake_resolver(PUBLIC_MAP))
    assert ip == "93.184.216.34"
    assert port == 443


@pytest.mark.parametrize("target", [
    "http://127.0.0.1/admin",
    "http://localhost:80/",
    "http://[::1]/",
])
def test_loopback_destinations_are_blocked(target):
    with pytest.raises(SSRFBlocked):
        security.validate_outbound_url(target, allowlist=ALLOW,
                                       resolver=fake_resolver({}))


@pytest.mark.parametrize("private_ip", [
    ["10.0.0.5"], ["172.16.4.9"], ["192.168.1.20"], ["127.0.0.1"],
])
def test_allowlisted_name_resolving_to_a_private_address_is_blocked(private_ip):
    """DNS rebinding: the name is approved but the answer is internal."""
    with pytest.raises(SSRFBlocked, match="restricted network"):
        security.validate_outbound_url(
            "https://docs.futminna.test/x", allowlist=ALLOW,
            resolver=fake_resolver({"docs.futminna.test": private_ip}))


def test_cloud_metadata_address_is_blocked():
    with pytest.raises(SSRFBlocked, match="restricted network"):
        security.validate_outbound_url(
            "http://docs.futminna.test/", allowlist=ALLOW,
            resolver=fake_resolver({"docs.futminna.test": ["169.254.169.254"]}))


def test_mixed_answer_with_one_internal_address_is_blocked():
    """One private answer condemns the whole name."""
    with pytest.raises(SSRFBlocked):
        security.validate_outbound_url(
            "https://docs.futminna.test/", allowlist=ALLOW,
            resolver=fake_resolver({"docs.futminna.test":
                                    ["93.184.216.34", "10.1.1.1"]}))


@pytest.mark.parametrize("target", [
    "file:///etc/passwd", "gopher://docs.futminna.test/", "ftp://docs.futminna.test/",
    "data:text/plain,hello",
])
def test_non_http_schemes_are_blocked(target):
    with pytest.raises(SSRFBlocked):
        security.validate_outbound_url(target, allowlist=ALLOW,
                                       resolver=fake_resolver(PUBLIC_MAP))


def test_non_standard_port_is_blocked():
    with pytest.raises(SSRFBlocked, match="port"):
        security.validate_outbound_url("http://docs.futminna.test:8080/",
                                       allowlist=ALLOW,
                                       resolver=fake_resolver(PUBLIC_MAP))


def test_host_outside_the_allowlist_is_blocked_without_resolving():
    calls = []

    def counting_resolver(host, port):
        calls.append(host)
        return ["93.184.216.34"]

    with pytest.raises(SSRFBlocked, match="approved list"):
        security.validate_outbound_url("https://unlisted.example.net/",
                                       allowlist=ALLOW, resolver=counting_resolver)
    assert calls == [], "a blocked host must not trigger a DNS lookup"


def test_embedded_credentials_are_rejected():
    with pytest.raises(SSRFBlocked, match="Credentials"):
        security.validate_outbound_url("https://docs.futminna.test@127.0.0.1/",
                                       allowlist=ALLOW,
                                       resolver=fake_resolver(PUBLIC_MAP))


def test_preview_endpoint_refuses_a_blocked_destination(logged_in):
    token = csrf_from(logged_in, "/documents/preview")
    response = logged_in.post("/documents/preview",
                              data={"url": "http://127.0.0.1:5000/admin",
                                    "csrf_token": token})
    assert response.status_code == 400
    body = response.get_data(as_text=True)
    assert "not permitted" in body
    # No preview block is rendered, so the endpoint returns nothing that could
    # be used to infer whether an internal host exists or how it responded.
    assert "Preview result" not in body
    assert "Resolved address" not in body


# ===========================================================================
# SECURITY MISCONFIGURATION
# ===========================================================================
REQUIRED_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
}


@pytest.mark.parametrize("header,value", REQUIRED_HEADERS.items())
def test_security_headers_present(client, header, value):
    assert client.get("/login").headers.get(header) == value


def test_permissions_policy_disables_sensitive_features(client):
    policy = client.get("/login").headers["Permissions-Policy"]
    for feature in ("geolocation", "microphone", "camera"):
        assert f"{feature}=()" in policy


def test_server_banner_does_not_disclose_the_stack(client):
    banner = client.get("/login").headers.get("Server", "")
    assert "Werkzeug" not in banner and "Python" not in banner


def test_debug_is_disabled(app):
    assert app.config["DEBUG"] is False


def test_production_profile_refuses_a_missing_secret_key(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    from secure_app import create_app
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app("production")


def test_no_credentials_are_hardcoded_in_the_source():
    suspicious = ("password = \"", "password='", "SECRET_KEY = \"", "api_key = \"")
    for source in list((ROOT / "secure_app").glob("*.py")):
        text = source.read_text(encoding="utf-8").lower()
        for pattern in suspicious:
            assert pattern.lower() not in text, f"{source.name}: {pattern}"


def test_unhandled_error_returns_a_reference_not_a_stack_trace(app):
    @app.route("/__boom")
    def boom():
        raise RuntimeError("internal detail that must not be shown")

    response = app.test_client().get("/__boom")
    assert response.status_code == 500
    body = response.get_data(as_text=True)
    assert "internal detail that must not be shown" not in body
    assert "Traceback" not in body
    assert "Reference:" in body


def test_upload_rejects_a_disallowed_extension(logged_in):
    import io
    token = csrf_from(logged_in, "/dashboard")
    response = logged_in.post("/documents/upload", data={
        "csrf_token": token,
        "document": (io.BytesIO(b"echo test"), "notes.sh")},
        content_type="multipart/form-data", follow_redirects=True)
    assert "not accepted" in response.get_data(as_text=True)


def test_upload_rejects_content_that_contradicts_its_extension(logged_in):
    import io
    token = csrf_from(logged_in, "/dashboard")
    response = logged_in.post("/documents/upload", data={
        "csrf_token": token,
        "document": (io.BytesIO(b"not really a pdf"), "report.pdf")},
        content_type="multipart/form-data", follow_redirects=True)
    assert "do not match" in response.get_data(as_text=True)


def test_upload_accepts_a_valid_file_and_renames_it(logged_in, app):
    import io
    token = csrf_from(logged_in, "/dashboard")
    payload = b"%PDF-1.4\n% fictitious lab document\n"
    response = logged_in.post("/documents/upload", data={
        "csrf_token": token,
        "document": (io.BytesIO(payload), "../../evil name.pdf")},
        content_type="multipart/form-data", follow_redirects=True)
    assert "Document uploaded" in response.get_data(as_text=True)
    with app.app_context():
        row = database.query("SELECT original_name, stored_name FROM documents",
                             one=True)
    # The path component was stripped and the stored name was server-generated.
    assert "/" not in row["stored_name"] and ".." not in row["stored_name"]
    assert row["stored_name"] != row["original_name"]


# ===========================================================================
# LOGGING
# ===========================================================================
def read_log(app):
    path = Path(app.config["AUDIT_LOG"])
    if not path.exists():
        return []
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_failed_login_is_logged_with_who_what_when(client, app):
    token = csrf_from(client)
    client.post("/login", data={"email": LAB_STUDENT,
                                "password": "WrongPassword#2026",
                                "csrf_token": token})
    events = [e for e in read_log(app) if e["event"] == "auth.login"]
    assert events, "failed login must be recorded"
    record = events[-1]
    assert record["outcome"] == "failure"
    assert record["ts"] and record["source_ip"]
    assert record["subject"] == "login"


def test_denied_authorisation_is_logged(logged_in, app):
    logged_in.get("/admin")
    events = [e for e in read_log(app) if e["event"] == "authz.denied"]
    assert events and events[-1]["outcome"] == "denied"


def test_rejected_validation_is_logged(logged_in, app):
    token = csrf_from(logged_in, "/profile")
    logged_in.post("/profile", data={"department": "x" * 200, "level": "500",
                                     "phone": "", "bio": "",
                                     "csrf_token": token})
    events = [e for e in read_log(app) if e["event"] == "validation.rejected"]
    assert events and events[-1]["outcome"] == "denied"


def test_logs_never_contain_a_password_or_token(client, app):
    token = csrf_from(client)
    client.post("/login", data={"email": LAB_STUDENT,
                                "password": "WrongPassword#2026",
                                "csrf_token": token})
    raw = Path(app.config["AUDIT_LOG"]).read_text(encoding="utf-8")
    assert "WrongPassword#2026" not in raw
    assert token not in raw


def test_email_is_masked_in_logs(client, app):
    token = csrf_from(client)
    client.post("/login", data={"email": LAB_STUDENT,
                                "password": "WrongPassword#2026",
                                "csrf_token": token})
    raw = Path(app.config["AUDIT_LOG"]).read_text(encoding="utf-8")
    assert LAB_STUDENT not in raw          # full address absent
    assert "@lab.test" in raw              # domain retained for triage


def test_redaction_helper_masks_every_sensitive_key():
    cleaned = security.redact({
        "password": "SuperSecret#1", "otp": "123456",
        "csrf_token": "abc", "mfa_secret": "BASE32", "reason": "bad-credentials",
    })
    assert cleaned["password"] == "[REDACTED]"
    assert cleaned["otp"] == "[REDACTED]"
    assert cleaned["csrf_token"] == "[REDACTED]"
    assert cleaned["mfa_secret"] == "[REDACTED]"
    assert cleaned["reason"] == "bad-credentials"   # non-secret detail retained


def test_ssrf_rejection_is_logged(logged_in, app):
    token = csrf_from(logged_in, "/documents/preview")
    logged_in.post("/documents/preview",
                   data={"url": "http://169.254.169.254/latest/meta-data/",
                         "csrf_token": token})
    events = [e for e in read_log(app) if e["event"] == "ssrf.blocked"]
    assert events and events[-1]["outcome"] == "denied"


def test_csrf_rejection_is_logged(logged_in, app):
    logged_in.post("/courses/register", data={"course_id": 1})
    events = [e for e in read_log(app) if e["event"] == "csrf.rejected"]
    assert events and events[-1]["outcome"] == "denied"


def test_database_audit_table_receives_events(logged_in, app):
    with app.app_context():
        rows = database.query("SELECT event, outcome FROM audit_log")
    assert any(r["event"] == "auth.login" and r["outcome"] == "success"
               for r in rows)
