"""
tests/test_auth.py
==================
Task 2 evidence: authentication and session controls.

Covers the four required outcomes - valid login works, invalid credentials are
rejected, stored passwords are not plaintext - plus the supplementary controls
(lockout, rate limiting, MFA, session regeneration).
"""

import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from secure_app import db as database, security          # noqa: E402
from tests.conftest import (LAB_ADMIN, LAB_ADMIN_PASSWORD,  # noqa: E402
                            LAB_STUDENT, LAB_STUDENT_PASSWORD, csrf_from)


# ---------------------------------------------------------------------------
# Password storage
# ---------------------------------------------------------------------------
def test_stored_password_is_an_argon2id_hash_not_plaintext(app):
    with app.app_context():
        row = database.find_user_by_email(LAB_STUDENT)
    stored = row["password_hash"]
    assert stored.startswith("$argon2id$"), stored[:20]
    assert LAB_STUDENT_PASSWORD not in stored
    assert len(stored) > 60


def test_identical_passwords_produce_different_hashes():
    """Per-password salting: no two stored values match, so one cracked hash
    does not reveal every account sharing that password."""
    a = security.hash_password("SameInputPassword#1")
    b = security.hash_password("SameInputPassword#1")
    assert a != b
    assert security.verify_password(a, "SameInputPassword#1")
    assert security.verify_password(b, "SameInputPassword#1")


def test_hash_encodes_expected_cost_parameters():
    encoded = security.hash_password("CostParameterCheck#1")
    assert "m=19456" in encoded and "t=2" in encoded and "p=1" in encoded


def test_verification_rejects_a_wrong_password():
    encoded = security.hash_password("CorrectHorse#Battery1")
    assert security.verify_password(encoded, "CorrectHorse#Battery1") is True
    assert security.verify_password(encoded, "CorrectHorse#Battery2") is False


def test_verification_of_absent_account_still_returns_false():
    """No hash, no crash, no early exit that would leak account existence."""
    assert security.verify_password(None, "anything-at-all") is False


# ---------------------------------------------------------------------------
# Login outcomes
# ---------------------------------------------------------------------------
def test_valid_login_succeeds_and_creates_a_session(client):
    token = csrf_from(client)
    response = client.post("/login", data={"email": LAB_STUDENT,
                                           "password": LAB_STUDENT_PASSWORD,
                                           "csrf_token": token})
    assert response.status_code == 302
    assert "/dashboard" in response.headers["Location"]
    with client.session_transaction() as sess:
        assert sess["user_id"] == 1
        assert sess["role"] == "student"


def test_invalid_password_is_rejected(client):
    token = csrf_from(client)
    response = client.post("/login", data={"email": LAB_STUDENT,
                                           "password": "WrongPassword#2026",
                                           "csrf_token": token})
    assert response.status_code == 401
    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_unknown_and_known_accounts_return_the_same_message(client):
    """No user enumeration through differing responses."""
    token = csrf_from(client)
    unknown = client.post("/login", data={"email": "nobody@lab.test",
                                          "password": "WrongPassword#2026",
                                          "csrf_token": token})
    token = csrf_from(client)
    known = client.post("/login", data={"email": LAB_STUDENT,
                                        "password": "WrongPassword#2026",
                                        "csrf_token": token})
    assert unknown.status_code == known.status_code == 401
    assert "Invalid credentials" in unknown.get_data(as_text=True)
    assert "Invalid credentials" in known.get_data(as_text=True)


def test_login_page_never_leaks_database_detail(client):
    token = csrf_from(client)
    response = client.post("/login", data={"email": "nobody@lab.test",
                                           "password": "WrongPassword#2026",
                                           "csrf_token": token})
    body = response.get_data(as_text=True)
    for leak in ("sqlite3", "Traceback", "no such column", "OperationalError"):
        assert leak not in body


# ---------------------------------------------------------------------------
# C1: temporary account lockout
# ---------------------------------------------------------------------------
def test_account_locks_after_repeated_failures(client, app):
    for _ in range(security.MAX_ACCOUNT_FAILURES):
        token = csrf_from(client)
        client.post("/login", data={"email": LAB_STUDENT,
                                    "password": "WrongPassword#2026",
                                    "csrf_token": token})

    with app.app_context():
        row = database.find_user_by_email(LAB_STUDENT)
        assert row["failed_attempts"] >= security.MAX_ACCOUNT_FAILURES
        assert security.is_locked(row["locked_until"]) is True

    # The correct password is now refused while the lock stands ...
    token = csrf_from(client)
    response = client.post("/login", data={"email": LAB_STUDENT,
                                           "password": LAB_STUDENT_PASSWORD,
                                           "csrf_token": token})
    assert response.status_code == 401
    # ... and the refusal is worded identically to any other failure.
    assert "Invalid credentials" in response.get_data(as_text=True)


def test_lockout_is_temporary_not_permanent(app):
    """The expiry is a bounded window, so lockout cannot be used to deny a
    student access indefinitely."""
    expiry = security.parse_iso(security.lock_expiry())
    delta = (expiry - security.utc_now()).total_seconds() / 60
    assert 0 < delta <= security.ACCOUNT_LOCK_MINUTES + 1


def test_successful_login_clears_the_failure_counter(client, app):
    for _ in range(2):
        token = csrf_from(client)
        client.post("/login", data={"email": LAB_STUDENT,
                                    "password": "WrongPassword#2026",
                                    "csrf_token": token})
    token = csrf_from(client)
    client.post("/login", data={"email": LAB_STUDENT,
                                "password": LAB_STUDENT_PASSWORD,
                                "csrf_token": token})
    with app.app_context():
        row = database.find_user_by_email(LAB_STUDENT)
        assert row["failed_attempts"] == 0
        assert row["locked_until"] is None


# ---------------------------------------------------------------------------
# C2: per-source rate limiting
# ---------------------------------------------------------------------------
def test_source_ip_rate_limit_engages(client, app):
    with app.app_context():
        for i in range(security.MAX_IP_FAILURES):
            database.record_login_attempt(f"spray{i}@lab.test", "127.0.0.1", False)

    token = csrf_from(client)
    response = client.post("/login", data={"email": "student.two@lab.test",
                                           "password": "WrongPassword#2026",
                                           "csrf_token": token})
    assert response.status_code == 429
    assert "Too many attempts" in response.get_data(as_text=True)


def test_failure_counting_is_windowed(app):
    """Old failures fall out of the window and stop counting."""
    with app.app_context():
        database.record_login_attempt("a@lab.test", "10.0.0.9", False)
        recent = database.count_recent_failures_for_ip(
            "10.0.0.9", security.window_start(security.IP_WINDOW_MINUTES))
        assert recent == 1
        future_window = security.sql_window(-5)   # a window starting 5 min ahead
        assert database.count_recent_failures_for_ip("10.0.0.9", future_window) == 0


# ---------------------------------------------------------------------------
# C3: MFA for the privileged role
# ---------------------------------------------------------------------------
def test_admin_login_requires_a_second_factor(client):
    token = csrf_from(client)
    response = client.post("/login", data={"email": LAB_ADMIN,
                                           "password": LAB_ADMIN_PASSWORD,
                                           "csrf_token": token})
    assert response.status_code == 302
    assert "/login/mfa" in response.headers["Location"]
    # The password alone did NOT establish an authenticated session.
    with client.session_transaction() as sess:
        assert "user_id" not in sess
        assert sess["pending_mfa_user"] == 2


def test_admin_session_established_only_after_valid_otp(client, app):
    token = csrf_from(client)
    client.post("/login", data={"email": LAB_ADMIN, "password": LAB_ADMIN_PASSWORD,
                                "csrf_token": token})
    with app.app_context():
        secret = database.query("SELECT mfa_secret FROM users WHERE id = 2",
                                one=True)["mfa_secret"]

    token = csrf_from(client, "/login/mfa")
    wrong = client.post("/login/mfa", data={"code": "000000", "csrf_token": token})
    assert wrong.status_code == 401

    token = csrf_from(client, "/login/mfa")
    good = client.post("/login/mfa",
                       data={"code": security.current_totp(secret),
                             "csrf_token": token})
    assert good.status_code == 302
    with client.session_transaction() as sess:
        assert sess["role"] == "admin"


def test_totp_accepts_small_clock_drift_and_rejects_stale_codes():
    secret = security.generate_totp_secret()
    now = time.time()
    assert security.verify_totp(secret, security.current_totp(secret, now), now)
    one_step_ago = security.current_totp(secret, now - security.TOTP_STEP)
    assert security.verify_totp(secret, one_step_ago, now) is True
    far_past = security.current_totp(secret, now - 600)
    assert security.verify_totp(secret, far_past, now) is False


@pytest.mark.parametrize("bad", ["", None, "abcdef", "12345", "1234567"])
def test_totp_rejects_malformed_codes(bad):
    assert security.verify_totp(security.generate_totp_secret(), bad) is False


# ---------------------------------------------------------------------------
# C4: session regeneration and authorisation
# ---------------------------------------------------------------------------
def test_session_identifier_changes_on_login(client):
    with client.session_transaction() as sess:
        sess["planted"] = "attacker-controlled-value"
        sess["sid"] = "pre-auth-identifier"
    token = csrf_from(client)
    client.post("/login", data={"email": LAB_STUDENT,
                                "password": LAB_STUDENT_PASSWORD,
                                "csrf_token": token})
    with client.session_transaction() as sess:
        assert sess["sid"] != "pre-auth-identifier"   # fixation defeated
        assert "planted" not in sess                  # pre-auth state discarded


def test_logout_clears_the_session(logged_in):
    token = csrf_from(logged_in, "/dashboard")
    logged_in.post("/logout", data={"csrf_token": token})
    with logged_in.session_transaction() as sess:
        assert "user_id" not in sess
    assert logged_in.get("/dashboard").status_code == 302


def test_student_cannot_reach_the_admin_area(logged_in):
    assert logged_in.get("/admin").status_code == 403


def test_anonymous_user_is_redirected_from_protected_pages(client):
    for path in ("/dashboard", "/profile", "/courses", "/admin"):
        assert client.get(path).status_code == 302


def test_role_is_taken_from_the_session_not_from_the_request(logged_in):
    """A forged role in the request body must not grant privilege."""
    response = logged_in.get("/admin?role=admin",
                             headers={"X-Role": "admin"})
    assert response.status_code == 403


def test_password_change_requires_the_current_password(logged_in):
    token = csrf_from(logged_in, "/account/password")
    response = logged_in.post("/account/password", data={
        "current_password": "WrongPassword#2026",
        "new_password": "BrandNewPassword#1",
        "confirm_password": "BrandNewPassword#1",
        "csrf_token": token})
    assert response.status_code == 401


def test_password_change_rotates_the_stored_hash(logged_in, app):
    with app.app_context():
        before = database.find_user_by_email(LAB_STUDENT)["password_hash"]
    token = csrf_from(logged_in, "/account/password")
    response = logged_in.post("/account/password", data={
        "current_password": LAB_STUDENT_PASSWORD,
        "new_password": "BrandNewPassword#1",
        "confirm_password": "BrandNewPassword#1",
        "csrf_token": token})
    assert response.status_code == 302
    with app.app_context():
        after = database.find_user_by_email(LAB_STUDENT)["password_hash"]
    assert after != before
    assert security.verify_password(after, "BrandNewPassword#1")


# ---------------------------------------------------------------------------
# Regression: HEAD must not be processed as a credential submission.
#
# Found during evidence capture. `curl -I /login` returned 401 because the
# views tested `request.method == "GET"`; Flask allows HEAD implicitly, so a
# HEAD request fell through into the POST branch, failed validation and
# emitted a spurious failed-login audit event. Any monitoring tool or link
# checker issuing HEAD would have polluted the audit trail and driven accounts
# toward lockout. The views now test `!= "POST"`.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("path", ["/login", "/login/mfa"])
def test_head_request_is_not_treated_as_a_submission(client, path):
    response = client.head(path)
    assert response.status_code in (200, 302), (
        f"HEAD {path} returned {response.status_code}; it must not enter the "
        "POST branch")


def test_head_request_records_no_failed_login(client, app):
    import json as _json
    client.head("/login")
    log = Path(app.config["AUDIT_LOG"])
    events = ([_json.loads(l) for l in log.read_text().splitlines() if l.strip()]
              if log.exists() else [])
    assert not [e for e in events if e["event"] == "auth.login"]
