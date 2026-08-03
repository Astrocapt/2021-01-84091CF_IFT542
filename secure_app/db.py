"""
secure_app/db.py
================
Database access layer.

Design rule enforced throughout this module: **user input is never
concatenated, interpolated or formatted into SQL text.** Every value travels
to the engine through a bound parameter placeholder (`?`). The SQL statement
is parsed once by the engine, and the supplied values are then attached to the
already-compiled statement as data. Because parsing has finished before the
values are seen, no character inside a value can ever be read as SQL syntax.

The single helper `query()` is the only path to the database, which makes the
"no string-built SQL" rule mechanically checkable (see tests/test_sqli.py,
which greps the whole package for interpolation into SQL keywords).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import current_app, g

SCHEMA_FILE = Path(__file__).resolve().parent.parent / "migrations" / "001_schema.sql"


def get_db() -> sqlite3.Connection:
    """Return the request-scoped connection, opening it on first use."""
    if "db" not in g:
        conn = sqlite3.connect(
            current_app.config["DATABASE"],
            detect_types=sqlite3.PARSE_DECLTYPES,
            timeout=10,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def close_db(_exception=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def query(sql: str, params: tuple | list = (), *, one: bool = False,
          commit: bool = False):
    """
    Execute a parameterised statement.

    Parameters
    ----------
    sql     : SQL text containing ``?`` placeholders only. Callers must never
              build this string from request data.
    params  : the values bound to those placeholders, passed as data.
    one     : return a single row instead of a list.
    commit  : commit the transaction and return the cursor (for writes).
    """
    conn = get_db()
    cursor = conn.execute(sql, tuple(params))
    if commit:
        conn.commit()
        return cursor
    if one:
        return cursor.fetchone()
    return cursor.fetchall()


def init_db(app) -> None:
    """Apply the migration file to a fresh database."""
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.executescript(SCHEMA_FILE.read_text(encoding="utf-8"))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Typed accessors. Each one is a worked example of the parameterisation rule.
# ---------------------------------------------------------------------------

def find_user_by_email(email: str):
    """
    Retrieve the account by identifier ONLY.

    Note what this query does not do: it does not accept the password. The
    password is verified in application code against the stored hash
    (secure_app/security.py :: verify_password). Passing a password into SQL
    at all would require it to be comparable in the database, which in turn
    would require it to be stored reversibly or unsalted.
    """
    return query(
        "SELECT id, email, matric_no, full_name, password_hash, role, "
        "       mfa_secret, mfa_enabled, failed_attempts, locked_until "
        "FROM users WHERE email = ?",
        (email,),
        one=True,
    )


def find_user_by_id(user_id: int):
    return query(
        "SELECT id, email, matric_no, full_name, role, mfa_enabled "
        "FROM users WHERE id = ?",
        (user_id,),
        one=True,
    )


def record_login_attempt(email: str, source_ip: str, successful: bool) -> None:
    # The timestamp is supplied explicitly rather than left to the column
    # default, so that it is written in the same textual format the rate-limit
    # window query compares against.
    from .security import sql_now
    query(
        "INSERT INTO login_attempts (email, source_ip, successful, attempted_at) "
        "VALUES (?, ?, ?, ?)",
        (email, source_ip, 1 if successful else 0, sql_now()),
        commit=True,
    )


def count_recent_failures_for_ip(source_ip: str, since_iso: str) -> int:
    row = query(
        "SELECT COUNT(*) AS n FROM login_attempts "
        "WHERE source_ip = ? AND successful = 0 AND attempted_at >= ?",
        (source_ip, since_iso),
        one=True,
    )
    return row["n"] if row else 0


def set_failed_attempts(user_id: int, count: int, locked_until: str | None) -> None:
    query(
        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
        (count, locked_until, user_id),
        commit=True,
    )


def clear_lockout(user_id: int) -> None:
    query(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
        (user_id,),
        commit=True,
    )


def update_password_hash(user_id: int, new_hash: str) -> None:
    query(
        "UPDATE users SET password_hash = ?, password_changed_at = datetime('now') "
        "WHERE id = ?",
        (new_hash, user_id),
        commit=True,
    )


def get_profile(user_id: int):
    return query("SELECT * FROM profiles WHERE user_id = ?", (user_id,), one=True)


def upsert_profile(user_id: int, department: str, level: str,
                   phone: str, bio: str) -> None:
    query(
        "INSERT INTO profiles (user_id, department, level, phone, bio, updated_at) "
        "VALUES (?, ?, ?, ?, ?, datetime('now')) "
        "ON CONFLICT(user_id) DO UPDATE SET "
        "  department = excluded.department, level = excluded.level, "
        "  phone = excluded.phone, bio = excluded.bio, "
        "  updated_at = excluded.updated_at",
        (user_id, department, level, phone, bio),
        commit=True,
    )


def list_courses(search: str | None = None):
    """
    Optional search term. The term is bound as a parameter; only the LIKE
    wildcards are added by the application, never by the user.
    """
    if search:
        return query(
            "SELECT id, code, title, units, semester, capacity FROM courses "
            "WHERE code LIKE ? OR title LIKE ? ORDER BY code",
            (f"%{search}%", f"%{search}%"),
        )
    return query(
        "SELECT id, code, title, units, semester, capacity FROM courses ORDER BY code"
    )


def list_enrolments(user_id: int):
    return query(
        "SELECT e.id, c.code, c.title, c.units, e.created_at "
        "FROM enrolments e JOIN courses c ON c.id = e.course_id "
        "WHERE e.user_id = ? ORDER BY c.code",
        (user_id,),
    )


def course_exists(course_id: int) -> bool:
    return query("SELECT 1 FROM courses WHERE id = ?", (course_id,), one=True) is not None


def enrol(user_id: int, course_id: int) -> bool:
    """Returns False when the student is already registered for the course."""
    try:
        query(
            "INSERT INTO enrolments (user_id, course_id) VALUES (?, ?)",
            (user_id, course_id),
            commit=True,
        )
        return True
    except sqlite3.IntegrityError:
        return False


def drop_enrolment(user_id: int, course_id: int) -> int:
    cur = query(
        "DELETE FROM enrolments WHERE user_id = ? AND course_id = ?",
        (user_id, course_id),
        commit=True,
    )
    return cur.rowcount


def save_document(user_id: int, original_name: str, stored_name: str,
                  content_type: str, size_bytes: int, sha256: str) -> None:
    query(
        "INSERT INTO documents (user_id, original_name, stored_name, "
        "content_type, size_bytes, sha256) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, original_name, stored_name, content_type, size_bytes, sha256),
        commit=True,
    )


def list_documents(user_id: int):
    return query(
        "SELECT id, original_name, content_type, size_bytes, uploaded_at "
        "FROM documents WHERE user_id = ? ORDER BY uploaded_at DESC",
        (user_id,),
    )


def write_audit(event: str, actor: str, subject: str | None, outcome: str,
                source_ip: str | None, detail: str | None) -> None:
    query(
        "INSERT INTO audit_log (event, actor, subject, outcome, source_ip, detail) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (event, actor, subject, outcome, source_ip, detail),
        commit=True,
    )
