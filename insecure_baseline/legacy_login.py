"""
insecure_baseline/legacy_login.py
=================================
THE "BEFORE" STATE - DO NOT DEPLOY. NOT IMPORTED BY THE RUNNING APPLICATION.

This file preserves the authentication code of the original prototype exactly
as it was found during the review, so that the report can show a genuine
before/after comparison and so that the regression tests can prove the
weakness is gone from the hardened build.

It is loaded only by tests/test_sqli.py, against a throwaway in-memory
database seeded with fictitious data. It is never registered with Flask, never
bound to a port, and never given real data.

Three defects are preserved here deliberately:

    D1  SQL text is assembled by string interpolation from request input, so
        input can alter the structure of the statement rather than only its
        values.                                    -> CWE-89
    D2  Passwords are stored and compared as plaintext.
                                                   -> CWE-256 / CWE-257
    D3  Database exception text is returned to the client, disclosing schema
        and engine internals.                      -> CWE-209
"""

import sqlite3


# ---------------------------------------------------------------------------
# D1 + D2: authentication by string-built SQL against plaintext passwords
# ---------------------------------------------------------------------------
def legacy_authenticate(conn: sqlite3.Connection, email: str, password: str):
    """
    Original prototype login check.

    The statement is built by interpolation, and the password is compared
    inside SQL. Both are wrong:

      * Because the values are pasted into the statement before the engine
        parses it, the engine cannot tell which characters were meant as data.
        Anything the submitted string contains is parsed as part of the
        command, so the submitted value can change what the command *means*
        rather than merely what it matches.

      * Comparing the password in SQL requires the stored value to be
        directly comparable, which forces plaintext (or an unsalted digest)
        storage. A single read of the users table then exposes every account,
        and because students reuse passwords, every account elsewhere too.
    """
    sql = (
        "SELECT id, email, role FROM users "
        f"WHERE email = '{email}' AND password = '{password}'"
    )
    cursor = conn.execute(sql)          # <-- structure now depends on input
    return cursor.fetchone(), sql


# ---------------------------------------------------------------------------
# D1 again, in a read path: course search
# ---------------------------------------------------------------------------
def legacy_course_search(conn: sqlite3.Connection, term: str):
    sql = f"SELECT code, title FROM courses WHERE title LIKE '%{term}%'"
    return conn.execute(sql).fetchall(), sql


# ---------------------------------------------------------------------------
# D3: verbose error disclosure
# ---------------------------------------------------------------------------
def legacy_error_response(exc: Exception) -> str:
    """The prototype echoed the raw driver message straight back to the user."""
    return f"Database error: {exc}"


# ---------------------------------------------------------------------------
# Throwaway fixture used only by the regression tests.
# ---------------------------------------------------------------------------
LEGACY_SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    email TEXT,
    password TEXT,           -- plaintext, as in the original prototype
    role TEXT
);
CREATE TABLE courses (
    id INTEGER PRIMARY KEY,
    code TEXT,
    title TEXT
);
"""

# Fictitious lab data only.
LEGACY_SEED = [
    (1, "student.one@lab.test", "LabPassword1!", "student"),
    (2, "registrar@lab.test", "LabPassword2!", "admin"),
]


def build_legacy_fixture() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.executescript(LEGACY_SCHEMA)
    conn.executemany("INSERT INTO users VALUES (?, ?, ?, ?)", LEGACY_SEED)
    conn.executemany(
        "INSERT INTO courses (id, code, title) VALUES (?, ?, ?)",
        [(1, "IFT 542", "Web Application Security"),
         (2, "IFT 511", "Advanced Database Systems")],
    )
    conn.commit()
    return conn
