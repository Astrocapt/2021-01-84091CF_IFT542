"""
tests/test_sqli.py
==================
Task 2 evidence: unsafe input does not change query meaning.

The tests use one canonical textbook tautology string as a *test case*. It is
not an attack tool and is not tuned to any real system; it exists only to show
that the same input which subverts the legacy statement is treated as an inert
literal by the parameterised statement.

All work happens against a throwaway in-memory or temporary database holding
fictitious records. No external host is contacted.
"""

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from insecure_baseline.legacy_login import (build_legacy_fixture,   # noqa: E402
                                            legacy_authenticate)
from secure_app import db as database                              # noqa: E402
from secure_app import security                                    # noqa: E402
from tests.conftest import LAB_STUDENT, LAB_STUDENT_PASSWORD       # noqa: E402

# A classic always-true condition. Used only to compare behaviour before/after.
TAUTOLOGY = "' OR '1'='1"
COMMENT_TERMINATOR = "admin@lab.test'--"


# ---------------------------------------------------------------------------
# 1. The legacy statement IS subvertible (establishes the "before" state)
# ---------------------------------------------------------------------------
def test_legacy_statement_meaning_is_altered_by_input():
    conn = build_legacy_fixture()
    row, rendered_sql = legacy_authenticate(conn, TAUTOLOGY, TAUTOLOGY)

    # The submitted characters became part of the WHERE clause structure.
    assert "OR '1'='1'" in rendered_sql
    # And the statement now matches a row without a correct credential.
    assert row is not None, "legacy prototype should be subvertible"
    conn.close()


def test_legacy_statement_can_be_truncated_by_a_comment():
    conn = build_legacy_fixture()
    conn.execute("UPDATE users SET email='admin@lab.test' WHERE id=2")
    row, rendered_sql = legacy_authenticate(conn, COMMENT_TERMINATOR, "wrong")
    assert "--" in rendered_sql
    assert row is not None, "password check was commented out of the statement"
    conn.close()


# ---------------------------------------------------------------------------
# 2. The hardened data layer is NOT subvertible (establishes the "after" state)
# ---------------------------------------------------------------------------
def test_parameterised_lookup_treats_metacharacters_as_data(app):
    """
    The same input is passed straight into the hardened accessor, deliberately
    bypassing the input-validation layer, so that this test measures the
    parameterisation control on its own.
    """
    with app.app_context():
        assert database.find_user_by_email(TAUTOLOGY) is None
        assert database.find_user_by_email(COMMENT_TERMINATOR) is None
        # The genuine identifier still resolves, so the query is not simply broken.
        assert database.find_user_by_email(LAB_STUDENT) is not None


def test_parameterised_write_cannot_terminate_a_statement(app):
    """A value containing a statement separator is stored verbatim, not executed."""
    hostile_looking_title = "Systems'); DROP TABLE courses; --"
    with app.app_context():
        database.query("INSERT INTO courses (code, title) VALUES (?, ?)",
                       ("TST 101", hostile_looking_title), commit=True)
        # The table still exists and the value round-tripped unchanged.
        rows = database.query("SELECT title FROM courses WHERE code = ?", ("TST 101",))
        assert rows[0]["title"] == hostile_looking_title
        assert len(database.list_courses()) == 3


def test_search_filter_binds_the_term(app):
    """A quote in the search term returns no match rather than altering the query."""
    with app.app_context():
        assert database.list_courses("' OR 1=1 --") == []
        assert len(database.list_courses("Security")) == 1


# ---------------------------------------------------------------------------
# 3. The login endpoint rejects it at the validation layer too (defence in depth)
# ---------------------------------------------------------------------------
def test_login_endpoint_rejects_metacharacter_input(client):
    from tests.conftest import csrf_from
    token = csrf_from(client)
    response = client.post("/login", data={"email": TAUTOLOGY,
                                           "password": TAUTOLOGY,
                                           "csrf_token": token})
    assert response.status_code == 401
    body = response.get_data(as_text=True)
    # Generic message only: no SQL, no driver text, no hint about which field failed.
    assert "Invalid credentials" in body
    for leak in ("SELECT", "sqlite", "syntax", "Traceback", "WHERE"):
        assert leak not in body


# ---------------------------------------------------------------------------
# 4. Static guarantee: no SQL string is built from a variable anywhere in the app
# ---------------------------------------------------------------------------
# The scan parses each module and inspects the syntax tree rather than
# grepping the text, so comments and prose in docstrings cannot trigger a
# false positive and an obfuscated concatenation cannot hide from it.
SQL_KEYWORD_RE = re.compile(
    r"\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|WHERE|VALUES|ORDER\s+BY)\b",
    re.IGNORECASE,
)


def _looks_like_sql(text) -> bool:
    return isinstance(text, str) and bool(SQL_KEYWORD_RE.search(text))


def find_dynamic_sql(source_path: Path) -> list[str]:
    """Return a description of every place SQL text is built from a value."""
    import ast
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    findings = []

    for node in ast.walk(tree):
        # f"... WHERE x = {value}"
        if isinstance(node, ast.JoinedStr):
            literal = "".join(part.value for part in node.values
                              if isinstance(part, ast.Constant)
                              and isinstance(part.value, str))
            if _looks_like_sql(literal):
                findings.append(f"line {node.lineno}: f-string SQL")

        elif isinstance(node, ast.BinOp):
            left = node.left
            # "... WHERE x = %s" % value   /   "... WHERE " + value
            if isinstance(left, ast.Constant) and _looks_like_sql(left.value):
                if isinstance(node.op, ast.Mod):
                    findings.append(f"line {node.lineno}: percent-formatted SQL")
                elif isinstance(node.op, ast.Add) and not isinstance(
                        node.right, ast.Constant):
                    findings.append(f"line {node.lineno}: concatenated SQL")

        # "... WHERE x = {}".format(value)
        elif isinstance(node, ast.Call):
            func = node.func
            if (isinstance(func, ast.Attribute) and func.attr == "format"
                    and isinstance(func.value, ast.Constant)
                    and _looks_like_sql(func.value.value)):
                findings.append(f"line {node.lineno}: .format() SQL")

    return findings


@pytest.mark.parametrize("source", sorted((ROOT / "secure_app").glob("*.py")),
                         ids=lambda p: p.name)
def test_no_dynamically_built_sql_in_secure_app(source):
    findings = find_dynamic_sql(source)
    assert findings == [], f"{source.name} builds SQL dynamically: {findings}"


def test_the_scanner_itself_detects_the_legacy_pattern():
    """
    Control test: the scanner must flag the known-bad baseline file. Without
    this, a scanner that silently matched nothing would pass every check above
    and prove nothing.
    """
    findings = find_dynamic_sql(ROOT / "insecure_baseline" / "legacy_login.py")
    assert findings, "scanner failed to flag the known-vulnerable baseline"


def test_password_never_appears_in_any_sql_statement():
    """
    The hardened code retrieves the account by identifier and verifies the
    password in application code. No statement should reference a password
    column in a WHERE clause.
    """
    for source in (ROOT / "secure_app").glob("*.py"):
        text = source.read_text(encoding="utf-8")
        assert not re.search(r"WHERE[^\"']*password\s*=", text, re.IGNORECASE), source.name


# ---------------------------------------------------------------------------
# 5. Validation layer unit checks
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad", [
    "", "no-at-sign", "a@b", "x" * 250 + "@lab.test", TAUTOLOGY, None, 12345,
])
def test_email_validation_rejects_malformed_values(bad):
    with pytest.raises(security.ValidationError):
        security.validate_email(bad)


def test_email_validation_normalises_case_and_space():
    assert security.validate_email("  Student.One@LAB.test ") == LAB_STUDENT


@pytest.mark.parametrize("bad", ["short", "x" * 129, None, 42])
def test_password_length_bounds_enforced(bad):
    with pytest.raises(security.ValidationError):
        security.validate_password(bad)


def test_valid_password_accepted():
    assert security.validate_password(LAB_STUDENT_PASSWORD) == LAB_STUDENT_PASSWORD
