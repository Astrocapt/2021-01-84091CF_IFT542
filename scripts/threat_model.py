#!/usr/bin/env python3
"""
scripts/threat_model.py
=======================
The STRIDE worksheet and risk register for Task 1.

The data lives here rather than in a spreadsheet so that the register, the CSV
deliverables and the report all draw on one source and cannot drift apart.

Scoring method
--------------
Likelihood (1-5) and Impact (1-5) are assigned per threat against the state of
the application BEFORE remediation. Risk = Likelihood x Impact, giving a
1-25 scale banded as:

    1-6    Low         7-11   Moderate
    12-16  High        17-25  Critical

Residual scores are re-assessed against the same scale after the listed
controls are implemented and verified by the test suite.
"""

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"


def band(score: int) -> str:
    if score >= 17:
        return "Critical"
    if score >= 12:
        return "High"
    if score >= 7:
        return "Moderate"
    return "Low"


# ---------------------------------------------------------------------------
# id, STRIDE category, threat, DFD element(s), L, I, control type, control,
# residual L, residual I, status, verified-by
# ---------------------------------------------------------------------------
THREATS = [
    dict(
        id="T-01", category="Tampering",
        title="Authentication bypass through SQL injection in the login form",
        description=(
            "The prototype builds the login statement by interpolating the "
            "submitted e-mail and password into SQL text. Submitted characters "
            "are therefore parsed as part of the command, so the structure of "
            "the WHERE clause can be altered and the credential test removed "
            "entirely. The same pattern in the course search allows arbitrary "
            "read and write against every table."),
        elements="P1, D1, D3", likelihood=5, impact=5,
        control_type="Preventive",
        control=(
            "Replace every statement with a parameterised query so values bind "
            "as data after parsing; retrieve the account by identifier only; "
            "validate e-mail type, length and format before the data layer; "
            "route all access through a single db.query() helper."),
        residual_l=1, residual_i=5, status="Mitigated",
        verified="tests/test_sqli.py (11 tests)"),

    dict(
        id="T-02", category="Information Disclosure",
        title="Mass credential disclosure from plaintext password storage",
        description=(
            "Passwords are stored in a comparable form so they can be tested "
            "inside SQL. Any read of the users table - by injection, backup "
            "exposure or an insider - yields every student's password in clear "
            "text, and password reuse extends the loss to accounts on other "
            "systems."),
        elements="D1", likelihood=4, impact=5,
        control_type="Preventive",
        control=(
            "Store Argon2id hashes (m=19456, t=2, p=1) with a unique per-password "
            "salt; verify with the library's constant-time function; re-hash "
            "transparently when parameters change; never place a password in a "
            "SQL statement."),
        residual_l=1, residual_i=4, status="Mitigated",
        verified="tests/test_auth.py, evidence/captures/E6_password_storage.txt"),

    dict(
        id="T-03", category="Elevation of Privilege",
        title="Administrator session takeover via stored cross-site scripting",
        description=(
            "The profile biography is rendered without encoding. A student can "
            "store markup that executes when an administrator opens the record, "
            "running with the administrator's session and granting the student "
            "the ability to alter courses and enrolments."),
        elements="P2, P6, D2", likelihood=4, impact=4,
        control_type="Preventive",
        control=(
            "Render every user value through the auto-escaping template engine "
            "with no escape bypass; add a nonce-based Content-Security-Policy "
            "with no 'unsafe-inline'; set HttpOnly on the session cookie so a "
            "script cannot read it even if one executes."),
        residual_l=1, residual_i=4, status="Mitigated",
        verified="tests/test_defences.py, evidence/captures/E5_xss_encoding.txt"),

    dict(
        id="T-04", category="Spoofing",
        title="Impersonation of a student through credential stuffing",
        description=(
            "The login endpoint accepts unlimited attempts. Reused credentials "
            "from unrelated breaches can be replayed until one matches, letting "
            "an attacker act as that student."),
        elements="E2, P1, D1", likelihood=5, impact=3,
        control_type="Detective and Corrective",
        control=(
            "Temporary account lockout after 5 failures for 15 minutes; "
            "per-source-IP limiting of 20 failures in a 15-minute window; "
            "deliberately slow Argon2id verification; all attempts recorded to "
            "login_attempts and the audit log."),
        residual_l=2, residual_i=3, status="Accepted (residual)",
        verified="tests/test_auth.py, evidence/captures/E8_lockout_and_ratelimit.txt"),

    dict(
        id="T-05", category="Elevation of Privilege",
        title="Forced browsing to administrative functions",
        description=(
            "Administrative routes are reachable by URL and the role is trusted "
            "from client-supplied data, so any authenticated student can create "
            "or alter courses and read the enrolment of every other student."),
        elements="P6, D1, D3", likelihood=3, impact=5,
        control_type="Preventive and Detective",
        control=(
            "Decorate every privileged route with a server-side role check that "
            "reads the role from the session record only; deny by default; log "
            "each denial as an authz.denied event; require a second factor for "
            "the administrator role."),
        residual_l=1, residual_i=5, status="Mitigated",
        verified="tests/test_auth.py, evidence/captures/E12_access_control.txt"),

    dict(
        id="T-06", category="Information Disclosure",
        title="Internal network probing through the URL-preview feature",
        description=(
            "The document import fetches any URL the user supplies. Without a "
            "destination policy the server can be directed at loopback "
            "services, private ranges or a cloud instance-metadata endpoint, "
            "returning internal data to an external user."),
        elements="P5, E4", likelihood=3, impact=4,
        control_type="Preventive",
        control=(
            "Scheme and port allowlists; explicit host allowlist checked before "
            "resolution; rejection of any name resolving to a loopback, private, "
            "link-local, reserved or metadata address; connection pinned to the "
            "vetted address to close DNS rebinding; redirects disabled; refusal "
            "reason withheld from the client."),
        residual_l=1, residual_i=4, status="Mitigated",
        verified="tests/test_defences.py, evidence/captures/E4_ssrf_policy.txt"),

    dict(
        id="T-07", category="Information Disclosure",
        title="Schema and account enumeration through verbose responses",
        description=(
            "Driver exception text is returned to the browser and the login "
            "form distinguishes an unknown account from a wrong password, so an "
            "attacker can map the schema and build a list of valid identifiers "
            "before attempting any credential attack."),
        elements="P1", likelihood=4, impact=3,
        control_type="Preventive",
        control=(
            "One generic failure message for every authentication outcome; a "
            "dummy hash verification when the account is absent so response "
            "time does not differ; custom error handlers that return a reference "
            "code while the detail goes only to the server log."),
        residual_l=1, residual_i=3, status="Mitigated",
        verified="tests/test_auth.py, tests/test_defences.py"),

    dict(
        id="T-08", category="Tampering",
        title="Forged course registration via cross-site request forgery",
        description=(
            "Registration and profile updates change state on a cookie-"
            "authenticated POST. A page under the attacker's control can cause "
            "a signed-in student's browser to submit that request, altering the "
            "student's registration without their knowledge."),
        elements="E2, P2, P3, D3", likelihood=3, impact=3,
        control_type="Preventive",
        control=(
            "Per-session synchroniser token validated centrally on every unsafe "
            "method and compared in constant time; SameSite=Lax on the session "
            "cookie as an independent second layer; token rotated when the "
            "session is regenerated."),
        residual_l=1, residual_i=3, status="Mitigated",
        verified="tests/test_defences.py, evidence/captures/E3_csrf_enforcement.txt"),

    dict(
        id="T-09", category="Repudiation",
        title="Denial of a registration or enrolment change",
        description=(
            "Without a reliable record, a student can deny dropping a course "
            "and an administrator can deny altering an enrolment, leaving "
            "disputes unresolvable at the end of a semester."),
        elements="P3, P6, D6", likelihood=3, impact=3,
        control_type="Detective",
        control=(
            "Structured audit events recording actor, action, object, outcome, "
            "source address and timestamp for every state change and every "
            "denial, written to an append-only table and a JSON log; the "
            "application holds no UPDATE or DELETE against that table."),
        residual_l=2, residual_i=3, status="Accepted (residual)",
        verified="tests/test_defences.py, evidence/logs/security.log"),

    dict(
        id="T-10", category="Denial of Service",
        title="Resource exhaustion through unbounded document upload",
        description=(
            "The upload endpoint accepts any size and any type, so repeated "
            "large submissions can fill the disk and exhaust memory, and a file "
            "with a misleading extension may be stored under a type the rest of "
            "the system trusts."),
        elements="P4, D4", likelihood=3, impact=3,
        control_type="Preventive",
        control=(
            "2 MiB request ceiling enforced by the framework; extension and "
            "declared-type allowlists; magic-byte check that the content matches "
            "the claimed type; server-generated random storage name outside any "
            "served directory; 0600 permissions."),
        residual_l=2, residual_i=2, status="Mitigated",
        verified="tests/test_defences.py, evidence/captures/E13_upload_validation.txt"),

    dict(
        id="T-11", category="Denial of Service",
        title="Deliberate lockout of legitimate student accounts",
        description=(
            "The lockout control introduced for T-04 can itself be abused: an "
            "attacker who knows a student's e-mail can submit failed attempts "
            "on purpose to keep that student out during a registration window."),
        elements="P1, D1", likelihood=3, impact=2,
        control_type="Corrective",
        control=(
            "Lockout is time-bounded at 15 minutes rather than permanent and "
            "clears on the next successful sign-in; rate limiting is scoped to "
            "the source address so one host cannot lock many accounts; lockout "
            "events are logged so a targeted pattern is visible."),
        residual_l=3, residual_i=2, status="Accepted (residual)",
        verified="tests/test_auth.py::test_lockout_is_temporary_not_permanent"),
]

for t in THREATS:
    t["score"] = t["likelihood"] * t["impact"]
    t["residual"] = t["residual_l"] * t["residual_i"]
    t["band"] = band(t["score"])
    t["residual_band"] = band(t["residual"])

RANKED = sorted(THREATS, key=lambda t: (-t["score"], t["id"]))
for position, t in enumerate(RANKED, start=1):
    t["rank"] = position

TOP_THREE = RANKED[:3]
ACCEPTED = [t for t in THREATS if t["status"].startswith("Accepted")]

STRIDE_ORDER = ["Spoofing", "Tampering", "Repudiation",
                "Information Disclosure", "Denial of Service",
                "Elevation of Privilege"]


def coverage() -> dict:
    return {c: [t["id"] for t in THREATS if t["category"] == c]
            for c in STRIDE_ORDER}


def write_csvs() -> None:
    DOCS.mkdir(parents=True, exist_ok=True)

    with open(DOCS / "stride_worksheet.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ID", "STRIDE category", "Threat",
                         "DFD elements", "Description"])
        for t in sorted(THREATS, key=lambda x: STRIDE_ORDER.index(x["category"])):
            writer.writerow([t["id"], t["category"], t["title"],
                             t["elements"], t["description"]])

    with open(DOCS / "risk_register.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["Rank", "ID", "Category", "Threat", "Likelihood",
                         "Impact", "Risk score", "Priority band", "Control type",
                         "Control", "Residual L", "Residual I", "Residual score",
                         "Residual band", "Status", "Verified by"])
        for t in RANKED:
            writer.writerow([t["rank"], t["id"], t["category"], t["title"],
                             t["likelihood"], t["impact"], t["score"], t["band"],
                             t["control_type"], t["control"], t["residual_l"],
                             t["residual_i"], t["residual"], t["residual_band"],
                             t["status"], t["verified"]])

    print(f"Wrote docs/stride_worksheet.csv and docs/risk_register.csv "
          f"({len(THREATS)} threats)")
    print("STRIDE coverage:")
    for category, ids in coverage().items():
        print(f"  {category:<24} {', '.join(ids)}")
    print("\nTop three by risk score:")
    for t in TOP_THREE:
        print(f"  {t['rank']}. {t['id']} {t['title'][:52]:<52} "
              f"{t['likelihood']}x{t['impact']}={t['score']} -> {t['residual']}")


if __name__ == "__main__":
    write_csvs()
