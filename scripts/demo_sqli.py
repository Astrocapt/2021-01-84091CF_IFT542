#!/usr/bin/env python3
"""
scripts/demo_sqli.py
====================
Reproducible side-by-side demonstration for Task 2.

Runs one identical input through the legacy statement and through the
parameterised statement and reports what each does with it. Everything happens
against throwaway in-memory databases holding fictitious rows; no server, no
network, no real data.

Usage:  python scripts/demo_sqli.py
"""

import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from insecure_baseline.legacy_login import (build_legacy_fixture,
                                            legacy_authenticate)
from secure_app import security

# A textbook always-true condition, used purely as a comparison input.
TEST_INPUT = "' OR '1'='1"

LINE = "=" * 74


def build_hardened_fixture() -> sqlite3.Connection:
    """Same two fictitious accounts, but stored the hardened way."""
    conn = sqlite3.connect(":memory:")
    conn.execute("""CREATE TABLE users (
        id INTEGER PRIMARY KEY, email TEXT UNIQUE,
        password_hash TEXT, role TEXT)""")
    conn.executemany(
        "INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)",
        [(1, "student.one@lab.test",
          security.hash_password("LabPassword1!"), "student"),
         (2, "registrar@lab.test",
          security.hash_password("LabPassword2!"), "admin")])
    conn.commit()
    return conn


def hardened_authenticate(conn, email, password):
    """
    The corrected pattern: retrieve by identifier through a bound parameter,
    then verify the password in application code against the stored hash.
    """
    sql = "SELECT id, email, password_hash, role FROM users WHERE email = ?"
    row = conn.execute(sql, (email,)).fetchone()      # value bound as data
    if row is None:
        security.verify_password(None, password)      # uniform timing
        return None, sql
    if not security.verify_password(row[2], password):
        return None, sql
    return (row[0], row[1], row[3]), sql


def main() -> None:
    print("EVIDENCE E7 - SQL injection: before and after")
    print("Generated:", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    print("Fictitious in-memory data. No network access. No external database.")
    print(LINE)
    print(f"\nIdentical test input supplied to both implementations:  {TEST_INPUT!r}")
    print("(a textbook always-true condition, used only to compare behaviour)")

    # ---------------- BEFORE ----------------
    print("\n" + LINE)
    print("BEFORE  -  insecure_baseline/legacy_login.py :: legacy_authenticate()")
    print(LINE)
    legacy = build_legacy_fixture()
    row, rendered = legacy_authenticate(legacy, TEST_INPUT, TEST_INPUT)
    print("\nStatement the engine actually received:")
    print("   ", rendered)
    print("\nResult:", "ROW RETURNED - authentication bypassed" if row
          else "no row returned")
    if row:
        print(f"    matched account id={row[0]}  email={row[1]}  role={row[2]}")
    print("\nWhy: the value was pasted into the statement before parsing, so the")
    print("quote characters closed the literal and the remainder was read as")
    print("SQL syntax. The submitted data changed what the command MEANS.")
    legacy.close()

    # ---------------- AFTER ----------------
    print("\n" + LINE)
    print("AFTER   -  secure_app/db.py :: find_user_by_email() pattern")
    print(LINE)
    hardened = build_hardened_fixture()
    result, sql = hardened_authenticate(hardened, TEST_INPUT, TEST_INPUT)
    print("\nStatement text sent to the engine (fixed, parsed once):")
    print("   ", sql)
    print("Value bound separately as a parameter:")
    print("   ", repr(TEST_INPUT))
    print("\nResult:", "ROW RETURNED" if result else
          "no row returned - the input was treated as an ordinary string")
    print("\nWhy: parsing completes before the value is attached. The engine is")
    print("looking for an account whose email address is literally that string.")
    print("No such account exists, so nothing matches. No character inside the")
    print("value can be promoted to syntax, because syntax was already decided.")

    # ---------------- control still works ----------------
    print("\n" + LINE)
    print("CONTROL  -  the hardened path still authenticates a genuine account")
    print(LINE)
    ok, _ = hardened_authenticate(hardened, "student.one@lab.test", "LabPassword1!")
    print("\nValid credentials      ->", "accepted" if ok else "REJECTED (unexpected)")
    bad, _ = hardened_authenticate(hardened, "student.one@lab.test", "WrongPassword!")
    print("Wrong password         ->", "accepted (unexpected)" if bad else "rejected")
    unknown, _ = hardened_authenticate(hardened, "nobody@lab.test", "WrongPassword!")
    print("Unknown account        ->", "accepted (unexpected)" if unknown else "rejected")

    # ---------------- writes ----------------
    print("\n" + LINE)
    print("WRITE PATH  -  a separator inside a value does not terminate a statement")
    print(LINE)
    value = "Systems'); DROP TABLE users; --"
    hardened.execute("INSERT INTO users (id, email, password_hash, role) "
                     "VALUES (?, ?, ?, ?)", (9, value, "x", "student"))
    hardened.commit()
    stored = hardened.execute("SELECT email FROM users WHERE id = ?", (9,)).fetchone()[0]
    remaining = hardened.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    print(f"\nValue submitted : {value!r}")
    print(f"Value stored    : {stored!r}")
    print(f"users table     : still present, {remaining} rows")
    print("\nThe value round-tripped unchanged and no second statement executed.")
    hardened.close()

    print("\n" + LINE)
    print("Conclusion: the defect is behavioural, not cosmetic. Parameterisation")
    print("removes the attacker's ability to influence statement structure, which")
    print("is the property that makes the class of flaw exploitable at all.")
    print(LINE)


if __name__ == "__main__":
    main()
