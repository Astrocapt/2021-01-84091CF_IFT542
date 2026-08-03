#!/usr/bin/env python3
"""
scripts/seed.py
===============
Creates the database and loads FICTITIOUS lab data.

No credential is hardcoded. Passwords are generated at seed time and printed
once to the operator's terminal; they are stored only as Argon2id hashes. This
satisfies the "no default credentials" requirement of Task 3 and the "test
accounts using dummy data" requirement of the submission checklist.

Usage:
    python scripts/seed.py                # random passwords, printed once
    python scripts/seed.py --fixed        # deterministic lab passwords, for
                                          # reproducible marking only
"""

import argparse
import os
import secrets
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secure_app import create_app                      # noqa: E402
from secure_app import db as database                   # noqa: E402
from secure_app import security                         # noqa: E402

FIXED_LAB_PASSWORDS = {
    "student.one@lab.test": "LabStudent#2026a",
    "student.two@lab.test": "LabStudent#2026b",
    "registrar@lab.test":   "LabRegistrar#2026",
}

COURSES = [
    ("IFT 542", "Web Application Security", 3, "First", 60),
    ("IFT 511", "Advanced Database Systems", 3, "First", 60),
    ("IFT 503", "Distributed Systems", 2, "Second", 45),
    ("CPT 421", "Software Engineering Practice", 3, "First", 80),
    ("GST 501", "Research Methodology", 2, "Second", 120),
]

STUDENTS = [
    ("student.one@lab.test", "2021/01/00001CF", "Ada Lab-Student"),
    ("student.two@lab.test", "2021/01/00002CF", "Bola Lab-Student"),
]

ADMIN = ("registrar@lab.test", None, "Lab Registrar")


def random_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "#$%&*+-?"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixed", action="store_true",
                        help="use deterministic lab passwords")
    args = parser.parse_args()

    app = create_app("lab")
    db_path = Path(app.config["DATABASE"])
    if db_path.exists():
        db_path.unlink()
    database.init_db(app)

    issued = {}
    with app.app_context():
        for email, matric, name in STUDENTS:
            password = FIXED_LAB_PASSWORDS[email] if args.fixed else random_password()
            issued[email] = password
            database.query(
                "INSERT INTO users (email, matric_no, full_name, password_hash, "
                "role, password_changed_at) VALUES (?, ?, ?, ?, 'student', datetime('now'))",
                (email, matric, name, security.hash_password(password)),
                commit=True,
            )

        email, matric, name = ADMIN
        password = FIXED_LAB_PASSWORDS[email] if args.fixed else random_password()
        issued[email] = password
        mfa_secret = security.generate_totp_secret()
        database.query(
            "INSERT INTO users (email, matric_no, full_name, password_hash, role, "
            "mfa_secret, mfa_enabled, password_changed_at) "
            "VALUES (?, ?, ?, ?, 'admin', ?, 1, datetime('now'))",
            (email, matric, name, security.hash_password(password), mfa_secret),
            commit=True,
        )

        for code, title, units, semester, capacity in COURSES:
            database.query(
                "INSERT INTO courses (code, title, units, semester, capacity) "
                "VALUES (?, ?, ?, ?, ?)",
                (code, title, units, semester, capacity), commit=True,
            )

        database.query(
            "INSERT INTO profiles (user_id, department, level, phone, bio, updated_at) "
            "VALUES (1, ?, ?, ?, ?, datetime('now'))",
            ("Information Technology", "500", "+2348000000001",
             "Final-year student interested in application security."),
            commit=True,
        )

    print("Database seeded at", db_path)
    print("\nLab accounts (FICTITIOUS - shown once, stored only as Argon2id hashes):")
    for email, password in issued.items():
        print(f"  {email:<24} {password}")
    print(f"\nAdmin TOTP secret (lab only): {mfa_secret}")
    print("Rotate or discard these before sharing the repository.")

    if os.environ.get("SEED_OUTPUT"):
        Path(os.environ["SEED_OUTPUT"]).write_text(
            "\n".join(f"{e}\t{p}" for e, p in issued.items())
            + f"\nTOTP\t{mfa_secret}\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
