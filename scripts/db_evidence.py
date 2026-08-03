#!/usr/bin/env python3
"""
scripts/db_evidence.py
======================
Produces the database evidence for Task 2: proof that credentials are stored
as Argon2id hashes and not as plaintext.

The hash values are TRUNCATED in the output. A full Argon2 encoded string
contains the salt and digest; there is no reason to publish those in a report,
so only the algorithm identifier, cost parameters and a short prefix are shown.
"""

import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DB = ROOT / "instance" / "registration.sqlite3"

FIXED_LAB_PASSWORDS = [
    "LabStudent#2026a", "LabStudent#2026b", "LabRegistrar#2026",
]


def main() -> None:
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, email, role, password_hash, mfa_enabled, failed_attempts "
        "FROM users ORDER BY id"
    ).fetchall()

    from datetime import datetime, timezone
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "EVIDENCE E6 - Password storage in the users table",
        f"Captured: {stamp}",
        "Source: instance/registration.sqlite3 (lab database, fictitious accounts)",
        f"Query : SELECT id, email, role, password_hash FROM users",
        "",
        "Hash values are truncated: the salt and digest segments are withheld.",
        "=" * 78,
        "",
    ]

    for row in rows:
        encoded = row["password_hash"]
        parts = encoded.split("$")
        algorithm = parts[1] if len(parts) > 1 else "?"
        version = parts[2] if len(parts) > 2 else "?"
        params = parts[3] if len(parts) > 3 else "?"
        lines += [
            f"id            : {row['id']}",
            f"email         : {row['email']}",
            f"role          : {row['role']}",
            f"algorithm     : {algorithm}",
            f"version       : {version}",
            f"cost params   : {params}",
            f"stored value  : {encoded[:38]}...[salt and digest withheld]",
            f"stored length : {len(encoded)} characters",
            f"mfa_enabled   : {bool(row['mfa_enabled'])}",
            "",
        ]

    # --- verification checks ------------------------------------------------
    lines += ["=" * 78, "AUTOMATED CHECKS", "=" * 78, ""]

    all_argon = all(r["password_hash"].startswith("$argon2id$") for r in rows)
    lines.append(f"[{'PASS' if all_argon else 'FAIL'}] every stored value is an "
                 f"Argon2id encoded hash")

    stored_blob = " ".join(r["password_hash"] for r in rows)
    no_plaintext = not any(pw in stored_blob for pw in FIXED_LAB_PASSWORDS)
    lines.append(f"[{'PASS' if no_plaintext else 'FAIL'}] no known lab password "
                 f"appears anywhere in the stored values")

    distinct = len({r["password_hash"] for r in rows}) == len(rows)
    lines.append(f"[{'PASS' if distinct else 'FAIL'}] every stored hash is distinct "
                 f"(per-password salting)")

    # Confirm no column anywhere in the schema is named 'password'
    schema = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table'"
    ).fetchall()
    schema_text = " ".join(s["sql"] or "" for s in schema).lower()
    no_plain_column = "password text" not in schema_text
    lines.append(f"[{'PASS' if no_plain_column else 'FAIL'}] the schema declares no "
                 f"plaintext password column")

    # Confirm the login_attempts table records no credential material
    columns = [c[1] for c in conn.execute("PRAGMA table_info(login_attempts)")]
    lines += [
        "",
        f"login_attempts columns: {', '.join(columns)}",
        f"[{'PASS' if 'password' not in columns else 'FAIL'}] the attempt log stores "
        f"no credential value",
        "",
        "Verification of a live login is covered by tests/test_auth.py::"
        "test_stored_password_is_an_argon2id_hash_not_plaintext.",
    ]

    conn.close()
    print("\n".join(lines))


if __name__ == "__main__":
    main()
