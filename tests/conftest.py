"""
tests/conftest.py
=================
Fixtures. Every test runs against a throwaway SQLite file seeded with
fictitious data, created and destroyed per test. Nothing here touches a
network destination or any host other than the in-process test client.
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

LAB_STUDENT = "student.one@lab.test"
LAB_STUDENT_PASSWORD = "LabStudent#2026a"
LAB_ADMIN = "registrar@lab.test"
LAB_ADMIN_PASSWORD = "LabRegistrar#2026"


@pytest.fixture()
def app(tmp_path):
    db_fd, db_path = tempfile.mkstemp(suffix=".sqlite3")
    os.close(db_fd)
    log_path = tmp_path / "logs" / "security.log"

    os.environ["DATABASE_PATH"] = db_path
    os.environ["AUDIT_LOG_PATH"] = str(log_path)
    os.environ["SECRET_KEY"] = "test-only-key-not-used-outside-the-suite"

    from secure_app import create_app, db as database, security

    application = create_app("test")
    application.config["UPLOAD_DIR"] = tmp_path / "uploads"
    application.config["UPLOAD_DIR"].mkdir(parents=True, exist_ok=True)

    database.init_db(application)
    with application.app_context():
        database.query(
            "INSERT INTO users (email, matric_no, full_name, password_hash, role, "
            "password_changed_at) VALUES (?, ?, ?, ?, 'student', datetime('now'))",
            (LAB_STUDENT, "2021/01/00001CF", "Ada Lab-Student",
             security.hash_password(LAB_STUDENT_PASSWORD)),
            commit=True,
        )
        database.query(
            "INSERT INTO users (email, matric_no, full_name, password_hash, role, "
            "mfa_secret, mfa_enabled, password_changed_at) "
            "VALUES (?, ?, ?, ?, 'admin', ?, 1, datetime('now'))",
            (LAB_ADMIN, "STAFF/001", "Lab Registrar",
             security.hash_password(LAB_ADMIN_PASSWORD),
             security.generate_totp_secret()),
            commit=True,
        )
        for code, title in [("IFT 542", "Web Application Security"),
                            ("IFT 511", "Advanced Database Systems")]:
            database.query("INSERT INTO courses (code, title) VALUES (?, ?)",
                           (code, title), commit=True)

    yield application

    os.unlink(db_path)
    for key in ("DATABASE_PATH", "AUDIT_LOG_PATH"):
        os.environ.pop(key, None)


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf_from(client, path="/login"):
    """Read the anti-CSRF token the server issued for this session."""
    page = client.get(path)
    body = page.get_data(as_text=True)
    marker = 'name="csrf_token" value="'
    start = body.index(marker) + len(marker)
    return body[start:body.index('"', start)]


@pytest.fixture()
def logged_in(client):
    """A student session with a valid CSRF token."""
    token = csrf_from(client)
    client.post("/login", data={"email": LAB_STUDENT,
                                "password": LAB_STUDENT_PASSWORD,
                                "csrf_token": token},
                follow_redirects=True)
    return client
