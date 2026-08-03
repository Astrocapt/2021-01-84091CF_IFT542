# Student Registration Web Application — Secured Build

**IFT 542 — Web Application Security · Practical Assignment**
Federal University of Technology, Minna · Department of Information Technology

**Name:** Abayomi Favour T. · **Matriculation number:** 2021/01/84091CF

---

> **Authorised-lab restriction.** This application binds to `127.0.0.1` only and is intended to be run on your own machine. Every account, document and data value in it is fictitious. Do not point any part of it at a university system, a public website or any third-party service.

---

## 1. What this is

A prototype student registration application (login, profile, course registration, document upload, administrative management) that has been assessed against STRIDE and then hardened. The repository holds three things:

| Path | Purpose |
|---|---|
| `secure_app/` | The hardened application — the "after" state |
| `insecure_baseline/legacy_login.py` | The original defective authentication code, kept **only** as before-state evidence. Not imported by the running app. |
| `tests/` | 112 automated tests that prove each control works |

**Stack:** Python 3.12, Flask 3.1, SQLite 3, Argon2id (`argon2-cffi`). The assignment permits an approved server-side stack other than PHP/MySQL; the equivalent MySQL DDL is noted in §8.

## 2. Requirements

- Python 3.10 or newer
- `pip`
- No database server needed — SQLite ships with Python

## 3. Setup

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure secrets (never commit the resulting .env)
cp .env.example .env
python3 -c "import os; print(os.urandom(32).hex())"   # paste into SECRET_KEY

# 4. Create and seed the database with fictitious data
python3 scripts/seed.py
```

`scripts/seed.py` prints the generated lab passwords **once**. They exist only in your local SQLite file and are stored as Argon2id hashes.

## 4. Running

```bash
python3 run.py
```

Open <http://127.0.0.1:5000>. The server binds to loopback only; the host is not configurable from the environment.

## 5. Test accounts (fictitious)

Run the seed script with `--fixed` for the deterministic marking credentials below; without the flag it generates random ones.

```bash
python3 scripts/seed.py --fixed
```

| Account | Role | Password | Notes |
|---|---|---|---|
| `student.one@lab.test` | student | `LabStudent#2026a` | Has a seeded profile |
| `student.two@lab.test` | student | `LabStudent#2026b` | Used for the lockout demonstration |
| `registrar@lab.test` | admin | `LabRegistrar#2026` | Requires a TOTP second factor |

The administrator's TOTP secret is printed by the seed script. To obtain a current code without an authenticator app:

```bash
python3 -c "import sys; sys.path.insert(0,'.'); from secure_app.security import current_totp; print(current_totp('PASTE_SECRET_HERE'))"
```

These are throwaway values for a local database. They are not secrets and grant access to nothing else.

## 6. Reproducing the evidence

```bash
python3 -m pytest tests/ -v            # 112 tests -> evidence/captures/E9_test_results.txt
python3 scripts/seed.py --fixed        # reset to a known state
bash scripts/capture_evidence.sh      # live localhost captures E1-E13
python3 scripts/threat_model.py        # STRIDE worksheet + risk register CSVs
python3 scripts/make_dfd.py            # data-flow diagram (SVG + PNG)
python3 scripts/build_report.py        # the submitted PDF report
```

Run them in that order; the capture script expects a freshly seeded database.

## 7. Repository layout

```
2021-01-84091CF_IFT542/
├── README.md                    this file
├── run.py                       entry point (binds 127.0.0.1 only)
├── requirements.txt
├── .env.example                 template; real .env is git-ignored
├── secure_app/
│   ├── __init__.py              app factory: CSP, headers, CSRF, error handling
│   ├── config.py                profiles; no usable hardcoded secret
│   ├── security.py              hashing, validation, lockout, TOTP, CSRF, SSRF, logging
│   ├── db.py                    parameterised data-access layer
│   ├── auth.py                  login, MFA, session regeneration, password change
│   ├── routes.py                profile, courses, upload, URL preview, admin
│   ├── templates/               auto-escaped Jinja templates
│   └── static/app.css           external stylesheet (CSP forbids inline style)
├── insecure_baseline/
│   └── legacy_login.py          before-state only; not wired into the app
├── migrations/001_schema.sql
├── scripts/                     seed, evidence capture, threat model, DFD, report
├── tests/                       112 tests across three modules
├── docs/
│   ├── dfd.svg / dfd.png        Task 1 data-flow diagram
│   ├── stride_worksheet.csv     Task 1 STRIDE worksheet
│   ├── risk_register.csv        Task 1 risk register
│   ├── runbook.md               Task 3 six-stage incident-response runbook
│   ├── incident_record.md       Task 3 incident record
│   └── ethics_declaration.md    Task 3 signed ethics declaration
└── evidence/
    ├── logs/security.log        redacted JSON security log
    └── captures/E1-E13*.txt     numbered evidence items referenced by the report
```

## 8. Notes for the marker

**Why SQLite and Flask.** The assignment allows an approved server-side stack in place of PHP/MySQL. This choice lets the whole assessment run from a single `pip install` with no database server, so every piece of evidence in the report is reproducible on the marker's machine in under a minute. The security properties under assessment — parameter binding, slow salted hashing, output encoding, token validation — are engine-independent. The MySQL equivalent of the schema differs only in `INTEGER PRIMARY KEY AUTOINCREMENT` becoming `INT AUTO_INCREMENT PRIMARY KEY`, `TEXT` becoming `VARCHAR(n)`, and `datetime('now')` becoming `UTC_TIMESTAMP()`; the application code is unchanged because every value is already bound rather than interpolated.

**Where each requirement is evidenced.**

| Requirement | Where |
|---|---|
| Data-flow diagram with trust boundaries | `docs/dfd.png`, report §2.1 |
| STRIDE worksheet, ≥6 threats | `docs/stride_worksheet.csv` (11 threats, all six categories) |
| Risk register with residual risk | `docs/risk_register.csv`, report §2.3 |
| Before/after code with file paths | Report §3.1–3.2 |
| Hashed passwords, no real credentials | `evidence/captures/E6_password_storage.txt` |
| Authentication tests | `evidence/captures/E9_test_results.txt`, `E2`, `E8` |
| XSS / CSRF / SSRF / misconfiguration | `evidence/captures/E5`, `E3`, `E4`, `E1`, `E13` |
| Failed-login, denied-authz, rejected-validation logs | `evidence/logs/security.log` |
| Six-stage runbook | `docs/runbook.md` |
| Signed ethics declaration | `docs/ethics_declaration.md` |

**Known limitations.** Sessions are signed client-side cookies rather than a server-side store, so "regeneration" means discarding all pre-authentication state and minting a new identifier (see `auth.regenerate_session`); a server-side store would allow true server-initiated revocation. Rate-limit counters live in the application database, which is adequate for one process but would need a shared store behind multiple workers. The audit log is written to the same host as the application; off-host forwarding is recommended before any deployment beyond the lab.
