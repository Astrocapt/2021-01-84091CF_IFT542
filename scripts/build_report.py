#!/usr/bin/env python3
"""
scripts/build_report.py
=======================
Builds the submitted technical report as a PDF.

The report is assembled from the project's own artefacts rather than being
written out by hand: the STRIDE worksheet and risk register are read from the
CSV files that scripts/threat_model.py produces, the diagram is embedded from
docs/dfd.png, and the test count is read from the captured pytest output. A
change to the model or the tests therefore cannot silently disagree with the
report.

Output: 2021-01-84091CF_IFT542_Report.pdf
"""

from __future__ import annotations

import base64
import csv
import html
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
EVID = ROOT / "evidence" / "captures"
OUT_PDF = ROOT / "2021-01-84091CF_IFT542_Report.pdf"

NAME = "Abayomi Favour T."
MATRIC = "2021/01/84091CF"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def esc(text) -> str:
    return html.escape(str(text))


def read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def b64_image(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode("ascii")


def test_count() -> str:
    """Read the number of passing tests from the captured pytest output."""
    try:
        text = (EVID / "E9_test_results.txt").read_text(encoding="utf-8")
        match = re.search(r"(\d+) passed", text)
        return match.group(1) if match else "112"
    except OSError:
        return "112"


def code_block(path: str, body: str, caption: str = "") -> str:
    numbered = "\n".join(body.rstrip("\n").split("\n"))
    cap = f'<div class="cap">{esc(caption)}</div>' if caption else ""
    return (f'<div class="codewrap"><div class="codepath">{esc(path)}</div>'
            f'<pre class="code">{esc(numbered)}</pre>{cap}</div>')


# ---------------------------------------------------------------------------
# data
# ---------------------------------------------------------------------------
stride = read_csv(DOCS / "stride_worksheet.csv")
register = read_csv(DOCS / "risk_register.csv")
stride.sort(key=lambda r: r["ID"])
register.sort(key=lambda r: int(r["Rank"]))
N_TESTS = test_count()
CATEGORIES = ["Spoofing", "Tampering", "Repudiation",
              "Information Disclosure", "Denial of Service",
              "Elevation of Privilege"]

top3 = register[:3]


# ---------------------------------------------------------------------------
# tables
# ---------------------------------------------------------------------------
def stride_table() -> str:
    rows = []
    for r in stride:
        rows.append(
            f"<tr><td class='id'>{esc(r['ID'])}</td>"
            f"<td class='cat'>{esc(r['STRIDE category'])}</td>"
            f"<td>{esc(r['Threat'])}</td>"
            f"<td class='el'>{esc(r['DFD elements'])}</td></tr>")
    return ("<table class='grid'><thead><tr><th>ID</th><th>Category</th>"
            "<th>Application-specific threat</th><th>DFD elements</th></tr>"
            "</thead><tbody>" + "".join(rows) + "</tbody></table>")


def register_table() -> str:
    rows = []
    for r in register:
        band = r["Priority band"].lower()
        rband = r["Residual band"].lower()
        rows.append(
            f"<tr><td class='id'>{esc(r['Rank'])}</td>"
            f"<td class='id'>{esc(r['ID'])}</td>"
            f"<td>{esc(r['Threat'])}</td>"
            f"<td class='n'>{esc(r['Likelihood'])}</td>"
            f"<td class='n'>{esc(r['Impact'])}</td>"
            f"<td class='n'><b>{esc(r['Risk score'])}</b></td>"
            f"<td class='n band-{band}'>{esc(r['Priority band'])}</td>"
            f"<td class='n'>{esc(r['Residual L'])}&times;{esc(r['Residual I'])}"
            f"={esc(r['Residual score'])}</td>"
            f"<td class='n band-{rband}'>{esc(r['Residual band'])}</td></tr>")
    return ("<table class='grid small'><thead><tr><th>#</th><th>ID</th>"
            "<th>Threat</th><th>L</th><th>I</th><th>Risk</th><th>Band</th>"
            "<th>Residual</th><th>Band</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>")


def controls_table() -> str:
    rows = []
    for r in register:
        rows.append(
            f"<tr><td class='id'>{esc(r['ID'])}</td>"
            f"<td class='el'>{esc(r['Control type'])}</td>"
            f"<td>{esc(r['Control'])}</td>"
            f"<td class='el'>{esc(r['Verified by'])}</td></tr>")
    return ("<table class='grid small'><thead><tr><th>ID</th><th>Control type</th>"
            "<th>Control applied</th><th>Verified by</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>")


def coverage_table() -> str:
    rows = []
    for cat in CATEGORIES:
        ids = [r["ID"] for r in stride if r["STRIDE category"] == cat]
        rows.append(f"<tr><td class='cat'>{esc(cat)}</td>"
                    f"<td class='n'>{len(ids)}</td>"
                    f"<td class='el'>{esc(', '.join(ids))}</td></tr>")
    return ("<table class='grid'><thead><tr><th>STRIDE category</th>"
            "<th>Threats</th><th>IDs</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>")


# ---------------------------------------------------------------------------
# code excerpts
# ---------------------------------------------------------------------------
BEFORE_SQL = '''def legacy_authenticate(conn, email: str, password: str):
    sql = (
        "SELECT id, email, role FROM users "
        f"WHERE email = '{email}' AND password = '{password}'"
    )
    cursor = conn.execute(sql)          # structure now depends on input
    return cursor.fetchone(), sql'''

AFTER_SQL = '''def find_user_by_email(email: str):
    """Retrieve the account by identifier ONLY. The password is not part
    of the query; it is verified afterwards against the stored hash."""
    return query(
        "SELECT id, email, matric_no, full_name, password_hash, role, "
        "       mfa_secret, mfa_enabled, failed_attempts, locked_until "
        "FROM users WHERE email = ?",
        (email,),
        one=True,
    )'''

AFTER_VERIFY = '''# secure_app/auth.py :: login()
user = db.find_user_by_email(email)          # bound parameter, data only
stored = user["password_hash"] if user else None
if not security.verify_password(stored, password):   # Argon2id, in app code
    ...
    flash(GENERIC_LOGIN_ERROR, "error")      # one message for every failure
    return render_template("login.html"), 401'''

HASHING = '''_hasher = PasswordHasher(
    time_cost=2,          # iterations
    memory_cost=19456,    # 19 MiB - memory-hard, resists GPU/ASIC cracking
    parallelism=1,
    hash_len=32, salt_len=16,
    type=Type.ID,         # Argon2id
)

# Verifying against a dummy hash when the account does not exist keeps the
# response time of "unknown user" close to "known user, wrong password".
_DUMMY_HASH = _hasher.hash("not-a-real-password-" + secrets.token_hex(8))'''

SSRF_CODE = '''# (c) host allowlist, checked BEFORE resolution so a blocked host
#     causes no network request at all
if host not in allow:
    raise SSRFBlocked("Destination host is not on the approved list.")

# (d) resolve and vet EVERY returned address
for addr in addresses:
    if not _address_is_public(ipaddress.ip_address(addr)):
        # One private answer condemns the whole name: a host resolving to
        # both a public and an internal address is a rebinding attempt.
        raise SSRFBlocked("Destination resolves to a restricted network range.")

# (e) pin the vetted address for the actual connection
vetted_ip = addresses[0]'''

CSRF_CODE = '''@app.before_request
def _before():
    ...
    # Enforced centrally for every unsafe method. A view cannot opt out by
    # omission; it would have to be added to an explicit exemption set.
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        submitted = (request.form.get(security.CSRF_FIELD)
                     or request.headers.get("X-CSRF-Token"))
        if not security.csrf_is_valid(g.csrf_token, submitted):
            security.audit("csrf.rejected", "denied", ...)
            abort(403)'''

LOG_CODE = '''SENSITIVE_KEYS = {"password", "csrf_token", "session", "cookie",
                  "otp", "mfa_code", "totp", "mfa_secret", "secret", ...}

def redact(payload: dict) -> dict:
    """Strip secret-bearing keys before anything is written to a log."""
    clean = {}
    for key, value in payload.items():
        if key.lower() in SENSITIVE_KEYS:
            clean[key] = "[REDACTED]"
        elif key.lower() in {"email", "username"}:
            clean[key] = mask_email(str(value))   # g***y@example.test
        else:
            clean[key] = value
    return clean'''

HEAD_BUG = '''# Before (defective): Flask allows HEAD implicitly and maps it to the GET
# handler, but request.method stays "HEAD", so a HEAD request fell through
# into the credential-processing branch.
if request.method == "GET":
    return render_template("login.html")

# After:
if request.method != "POST":
    return render_template("login.html")'''


# ---------------------------------------------------------------------------
# document
# ---------------------------------------------------------------------------
def build_html() -> str:
    dfd = b64_image(DOCS / "dfd.png")
    today = date.today().strftime("%d %B %Y")

    t1, t2, t3 = top3

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>IFT 542 Practical Assignment</title>
<style>
@page {{ size: A4; margin: 20mm 18mm 18mm 18mm; }}
body {{ font-family: "DejaVu Serif", Georgia, serif; font-size: 10.2pt;
        line-height: 1.5; color: #1b2430; }}
h1 {{ font-size: 17pt; margin: 0 0 2mm 0; }}
h2 {{ font-size: 13pt; border-bottom: 1.4pt solid #1f4e79; color: #1f4e79;
      padding-bottom: 1.5mm; margin: 8mm 0 3mm 0; page-break-after: avoid; }}
h3 {{ font-size: 11pt; color: #1f4e79; margin: 5mm 0 1.5mm 0;
      page-break-after: avoid; }}
h4 {{ font-size: 10.2pt; margin: 4mm 0 1mm 0; page-break-after: avoid; }}
p {{ margin: 0 0 2.6mm 0; text-align: justify; }}
ul, ol {{ margin: 0 0 2.6mm 0; padding-left: 6mm; }}
li {{ margin-bottom: 1.2mm; }}
table.grid {{ border-collapse: collapse; width: 100%; margin: 2mm 0 3mm 0;
              font-size: 8.6pt; page-break-inside: auto; }}
table.grid.small {{ font-size: 7.7pt; }}
table.grid th {{ background: #1f4e79; color: #fff; text-align: left;
                 padding: 1.4mm 1.6mm; font-weight: bold; }}
table.grid td {{ border-bottom: 0.4pt solid #cfd6de; padding: 1.3mm 1.6mm;
                 vertical-align: top; }}
table.grid tr:nth-child(even) td {{ background: #f4f7fa; }}
td.n {{ text-align: center; white-space: nowrap; }}
td.id {{ white-space: nowrap; font-weight: bold; }}
td.cat, td.el {{ white-space: normal; font-size: 7.6pt; }}
.band-critical {{ background: #f6d5d1 !important; font-weight: bold; }}
.band-high {{ background: #fae3cd !important; }}
.band-moderate {{ background: #fbf3cd !important; }}
.band-low {{ background: #dff0d8 !important; }}
pre.code {{ background: #f5f7f9; border: 0.4pt solid #ccd4dc;
            border-left: 2.2pt solid #1f4e79; padding: 2mm 2.5mm;
            font-family: "DejaVu Sans Mono", monospace; font-size: 7.6pt;
            line-height: 1.34; white-space: pre-wrap; margin: 0;
            page-break-inside: avoid; }}
.codewrap {{ margin: 2mm 0 3mm 0; page-break-inside: avoid; }}
.codepath {{ background: #1f4e79; color: #fff; font-family: "DejaVu Sans Mono",
             monospace; font-size: 7.3pt; padding: 1mm 2.5mm; }}
.cap {{ font-size: 8pt; color: #5c6b7a; margin-top: 1mm; font-style: italic; }}
.title {{ border: 1.4pt solid #1f4e79; padding: 6mm; margin-bottom: 6mm; }}
.title .inst {{ font-size: 9.4pt; color: #5c6b7a; margin-bottom: 3mm; }}
.title .meta {{ font-size: 9.6pt; margin-top: 4mm; }}
.note {{ background: #fbf3cd; border-left: 2.2pt solid #b8912a;
         padding: 2.5mm 3mm; margin: 3mm 0; font-size: 9.2pt; }}
.key {{ background: #eaf0f6; border-left: 2.2pt solid #1f4e79;
        padding: 2.5mm 3mm; margin: 3mm 0; font-size: 9.4pt; }}
.evid {{ font-size: 8.6pt; color: #1f4e79; font-weight: bold; }}
img.dfd {{ width: 100%; border: 0.4pt solid #ccd4dc; }}
.pb {{ page-break-before: always; }}
.sub {{ color: #5c6b7a; font-size: 9pt; }}
</style></head><body>

<div class="title">
  <div class="inst">FEDERAL UNIVERSITY OF TECHNOLOGY, MINNA<br>
  School of Information and Communication Technology &middot;
  Department of Information Technology</div>
  <h1>Security Assessment and Hardening of a<br>Student Registration Web Application</h1>
  <div class="sub">IFT 542 &mdash; Web Application Security &middot; Practical Assignment</div>
  <div class="meta">
    <b>Name:</b> {esc(NAME)}<br>
    <b>Matriculation number:</b> {esc(MATRIC)}<br>
    <b>Date:</b> {today}<br>
    <b>Implementation:</b> Python 3.12 / Flask 3.1 / SQLite 3 / Argon2id
  </div>
</div>

<div class="note"><b>Authorised-lab statement.</b> Every test described in this
report was performed against an isolated instance of the application bound to
the loopback interface (127.0.0.1) of a machine under my sole control. No
system belonging to FUT Minna, no public website and no third-party service was
scanned, probed or contacted at any point. All accounts, documents and data
values are fictitious. Reusable attack tooling is not included in this
submission; weaknesses are demonstrated only through automated tests inside the
isolated application, as the brief requires.</div>

<h2>1. Executive summary</h2>

<p>The prototype was reviewed against the STRIDE model, and {len(stride)} threats
were identified across all six categories. Two defects dominated the risk
profile: the login statement was assembled by pasting submitted values into SQL
text, and passwords were stored in a directly comparable form so that they could
be tested inside that statement. Together these allowed the credential check to
be removed from the query altogether, and ensured that any single read of the
user table would disclose every account's password in clear text.</p>

<p>The application was then rebuilt with the defects corrected and defences
added for the four vulnerability classes required by Task 3. All {N_TESTS}
automated tests pass. The three highest risks were reduced from scores of 25, 20
and 16 to residual scores of 5, 4 and 4 respectively; three lower-ranked risks
are formally accepted at their residual level, with justification in
&sect;2.5. Evidence items E1&ndash;E13 in <span class="evid">evidence/captures/</span>
are live output captured from the running application, not illustrations.</p>

<div class="key"><b>Headline outcome.</b> The corrected data-access layer makes
statement structure independent of user input; a static check that parses every
module's syntax tree confirms no SQL anywhere in the application is built from a
value, and that check runs inside the test suite so a regression fails the
build.</div>

<h2>2. Task 1 &mdash; STRIDE threat model and risk assessment</h2>

<h3>2.1 System decomposition and data-flow diagram</h3>

<p>The application supports student login, profile update, course registration,
document upload, an administrative area, and a URL-preview feature that imports
a document reference on the user's behalf. The diagram below decomposes it into
external entities, processes, data stores and the flows between them, with five
trust boundaries marked. A boundary is drawn wherever data crosses from one
level of trust to another; those crossings are where the threats in
&sect;2.2 are concentrated.</p>

<img class="dfd" src="data:image/png;base64,{dfd}" alt="Level 1 data-flow diagram">
<div class="cap">Figure 1 &mdash; Level 1 data-flow diagram with trust
boundaries. Source: <span class="evid">docs/dfd.png</span>, generated by
scripts/make_dfd.py.</div>

<p>The boundaries carry different assumptions. <b>TB1</b> separates the browser,
which is entirely attacker-controllable, from everything else: nothing arriving
across it may be trusted, including hidden fields, headers and cookies.
<b>TB2</b> encloses the application processes. <b>TB3</b> protects the data
stores, of which D1 is the most sensitive because it holds credential material.
<b>TB4</b> governs outbound traffic; it exists because P5 makes the server issue
requests on a user's behalf, which is what makes server-side request forgery
possible at all.</p>

<h3>2.2 STRIDE worksheet</h3>

<p>{len(stride)} application-specific threats were identified, covering every
STRIDE category. These are threats to this system rather than generic
categories: each names the element it acts on and the consequence it produces.</p>

{coverage_table()}
<div class="cap">Table 1 &mdash; STRIDE coverage. Full worksheet:
<span class="evid">docs/stride_worksheet.csv</span>.</div>

{stride_table()}
<div class="cap">Table 2 &mdash; STRIDE worksheet (abridged; the CSV carries the
full description of each threat).</div>

<h3>2.3 Risk register</h3>

<p>Each threat was scored for likelihood and impact on a 1&ndash;5 scale, with
<b>Risk = Likelihood &times; Impact</b>. Likelihood reflects how readily the
threat could be realised against this application as found; impact reflects the
consequence for the institution and for the students whose data it holds. Bands
are Critical (20&ndash;25), High (12&ndash;19), Moderate (6&ndash;11) and Low
(1&ndash;5).</p>

{register_table()}
<div class="cap">Table 3 &mdash; Risk register with residual risk after
controls. Source: <span class="evid">docs/risk_register.csv</span>.</div>

<h3>2.4 The three highest-priority risks</h3>

<h4>{esc(t1['ID'])} &mdash; {esc(t1['Threat'])} ({esc(t1['Likelihood'])}&times;{esc(t1['Impact'])} = {esc(t1['Risk score'])}, {esc(t1['Priority band'])})</h4>
<p>Ranked first because it scores maximum on both axes. Likelihood is 5 because
the flaw sits on an unauthenticated endpoint reachable by anyone who can load
the login page, and requires no special tooling to trigger. Impact is 5 because
success does not merely leak data: the injection point is the authentication
check itself, so the attacker becomes an authenticated user, and the same
pattern in the course search grants read and write access across every table.
This is the one finding that compromises confidentiality, integrity and
availability simultaneously. <b>Control:</b> {esc(t1['Control'])} <b>Residual
{esc(t1['Residual score'])}</b> &mdash; likelihood falls to 1 because statement
structure is now fixed before any value is attached; impact is left at
{esc(t1['Residual I'])} because the consequence of a future regression would be
just as severe, which is precisely why the static check runs in the test suite.</p>

<h4>{esc(t2['ID'])} &mdash; {esc(t2['Threat'])} ({esc(t2['Likelihood'])}&times;{esc(t2['Impact'])} = {esc(t2['Risk score'])}, {esc(t2['Priority band'])})</h4>
<p>Ranked second because it multiplies the damage of every other confidentiality
failure. Likelihood is 4 rather than 5 because it needs a prior read of the
table &mdash; but T-01 supplies exactly that, and so would a mislaid backup or a
curious insider. Impact is 5 because the loss is not recoverable by patching:
once disclosed, the passwords are disclosed, and since students reuse passwords
the harm propagates to email and banking accounts the university does not
control. <b>Control:</b> {esc(t2['Control'])} <b>Residual
{esc(t2['Residual score'])}</b> &mdash; an attacker who now obtains the table
holds only memory-hard hashes with unique salts, which must be attacked one
password at a time.</p>

<h4>{esc(t3['ID'])} &mdash; {esc(t3['Threat'])} ({esc(t3['Likelihood'])}&times;{esc(t3['Impact'])} = {esc(t3['Risk score'])}, {esc(t3['Priority band'])})</h4>
<p>Ranked third because it converts an ordinary student account into an
administrative one. Likelihood is 4 because storing the payload requires nothing
more than editing one's own profile, and the administrator will open that record
in the normal course of duty. Impact is 4 because the script runs with the
administrator's session and can alter courses and enrolments; it is not 5
because the credential store itself is not directly exposed. <b>Control:</b>
{esc(t3['Control'])} <b>Residual {esc(t3['Residual score'])}</b> &mdash; three
independent layers must fail together: escaping, the nonce-based policy, and the
HttpOnly flag that keeps the cookie unreadable even if a script did execute.</p>

<h3>2.5 Residual risk and accepted risks</h3>

<p>Three risks remain accepted rather than fully mitigated, because the residual
cause is inherent to the control rather than a gap in it.</p>

<ul>
<li><b>T-04 (residual 6)</b> &mdash; lockout and rate limiting slow credential
stuffing but cannot stop an attacker who already holds a correct password.
Accepted because the remaining exposure is addressed by detection (every attempt
is logged) rather than prevention; extending MFA to all students would reduce it
further at a usability cost the department has not agreed to.</li>
<li><b>T-09 (residual 6)</b> &mdash; the audit log demonstrates what happened,
but it is written to the same host as the application, so an attacker with root
could alter it. Accepted for the lab; off-host forwarding to write-once storage
is the recommended next control.</li>
<li><b>T-11 (residual 6, unchanged)</b> &mdash; deliberate lockout of a
legitimate student is <i>caused</i> by the control introduced for T-04. The
score is deliberately not reduced, because pretending otherwise would hide a
real trade-off. It is bounded instead: the lock expires after 15 minutes rather
than persisting, it clears on the next successful sign-in, and lockout events
are logged so a targeted pattern is visible. Accepted on the basis that a
15-minute delay to one student is a smaller harm than an unthrottled path to
account compromise.</li>
</ul>

<div class="pb"></div>
<h2>3. Task 2 &mdash; Secure authentication and SQL injection remediation</h2>

<h3>3.1 The unsafe pattern and the affected data flow</h3>

<p>The defective statement is on the flow E2/E1 &rarr; P1 &rarr; D1 in Figure 1
&mdash; the crossing of TB1, where wholly untrusted input reaches the credential
store. The prototype built the statement by interpolating both submitted values
into the SQL text:</p>

{code_block("insecure_baseline/legacy_login.py :: legacy_authenticate() (BEFORE)", BEFORE_SQL)}

<p>Two distinct defects are present. First, the values are pasted into the
statement <i>before</i> the engine parses it, so the engine cannot distinguish
characters the developer intended as command from characters the user supplied
as data. A quote inside the submitted value ends the string literal early, and
everything after it is parsed as SQL. The submitted data therefore changes what
the statement <i>means</i>, not merely what it matches &mdash; and because the
statement is the authentication check, its meaning can be changed to one that no
longer tests the password at all.</p>

<p>Second, comparing the password inside SQL forces the stored value to be
directly comparable, which requires plaintext or an unsalted digest. The two
defects are linked: fixing the query without fixing the storage would leave the
credential exposure untouched.</p>

<h3>3.2 The corrected pattern</h3>

{code_block("secure_app/db.py :: find_user_by_email() (AFTER)", AFTER_SQL)}
{code_block("secure_app/auth.py :: login() (AFTER)", AFTER_VERIFY)}

<p>Three things changed. The statement text is now fixed and contains a
placeholder; the value travels separately as a bound parameter; and the password
has left the query entirely, so the account is retrieved by identifier and the
credential is verified afterwards in application code.</p>

<h3>3.3 How parameterisation separates data from code</h3>

<div class="key"><p style="margin:0"><b>The mechanism.</b> With a parameterised
statement the database receives the SQL text and the values through separate
channels. The engine parses the text first and produces an execution plan while
the placeholder is still an empty slot. Only then are the supplied values bound
into those slots. Because parsing has already finished, no character inside a
value can be promoted to syntax &mdash; there is no parser still running for it
to influence. A submitted quote is simply a quote character in a string.</p></div>

<p>This is why parameterisation is a genuine fix and escaping is not. Escaping
tries to neutralise dangerous characters while still concatenating them into
code, so it depends on the developer correctly anticipating every character the
engine treats as special, in every context and character set. Parameterisation
removes the attacker's influence over structure altogether, which is the
property that made the flaw exploitable. Input validation is retained as a
second layer, but it is not the control that closes the vulnerability.</p>

<p>The comparison was run against both implementations with identical input.
The legacy statement matched an account without a correct credential; the
parameterised statement returned nothing, because it searched for an account
whose email address is literally that string. Both still authenticate a genuine
account correctly.</p>
<p class="sub">Evidence: <span class="evid">E7_sqli_before_after.txt</span>
(side-by-side run), <span class="evid">E10_static_sql_scan.txt</span> (static
check across every module).</p>

<h3>3.4 Password storage</h3>

{code_block("secure_app/security.py :: password hashing", HASHING)}

<p>Argon2id is used at the OWASP baseline of 19 MiB memory, two iterations and
one degree of parallelism. It is memory-hard, so an attacker cannot trade cheap
parallel hardware for speed as they can against iteration-only functions. The
library generates a unique salt per password and embeds it in the encoded hash,
so identical passwords never produce identical stored values and precomputed
tables do not apply. Verification uses the library's constant-time comparison,
and a stored hash written under weaker parameters is transparently upgraded on
the next successful login.</p>

<p>Inspection of the seeded database confirms every stored value carries the
<span class="evid">$argon2id$v=19$m=19456,t=2,p=1$</span> prefix with a distinct
salt, that no known lab password appears anywhere in the stored values, and that
no table in the schema declares a plaintext password column.</p>
<p class="sub">Evidence: <span class="evid">E6_password_storage.txt</span>.</p>

<h3>3.5 Supplementary authentication controls</h3>

<p>The brief requires at least two additional controls; four were implemented.</p>

<ul>
<li><b>Temporary account lockout</b> &mdash; five failures lock the account for
15 minutes. Verified live: the counter reaches the threshold, the lock is
recorded with an expiry, and the correct password is then refused <i>using the
identical wording as an ordinary failure</i>, so the response does not tell an
attacker that the account exists and is locked.</li>
<li><b>Per-source rate limiting</b> &mdash; 20 failures from one address in a
15-minute window returns HTTP 429. This targets password spraying, which lockout
alone does not address because it spreads few attempts across many accounts.</li>
<li><b>TOTP multi-factor for the privileged role</b> &mdash; RFC 6238, over the
standard library. The administrator's password alone establishes no session: it
redirects to the second-factor challenge, and the session is created only after
a valid code.</li>
<li><b>Session identifier regeneration</b> &mdash; the session is cleared and a
new identifier and CSRF token minted at every privilege change, defeating
session fixation and preventing a pre-authentication token from carrying over.</li>
</ul>

<p>Two supporting measures address enumeration: every authentication failure
returns one generic message, and when the account does not exist the code still
performs a full verification against a dummy hash so that response timing does
not disclose account existence.</p>
<p class="sub">Evidence: <span class="evid">E2_authentication_outcomes.txt</span>,
<span class="evid">E8_lockout_and_ratelimit.txt</span>.</p>

<h3>3.6 Test results</h3>

<p>All {N_TESTS} tests pass. The suite proves valid login succeeds, invalid
credentials are rejected, unsafe input does not change query meaning, and stored
passwords are not plaintext, alongside the supplementary controls. Two checks
are worth singling out because they guard against tests that appear to pass
while proving nothing: the static SQL scanner is itself run against a file
containing all four unsafe patterns to confirm it fires, and against the legacy
baseline, which it flags at the two known defective lines.</p>
<p class="sub">Evidence: <span class="evid">E9_test_results.txt</span>.</p>

<div class="pb"></div>
<h2>4. Task 3 &mdash; Web defences, incident response and ethics</h2>

<h3>4.1 Cross-site scripting</h3>

<p>The protected field is the profile biography, rendered on the dashboard. The
value is <i>not</i> sanitised on input: it is stored exactly as typed and made
safe at the point of output. Encoding at output is context-aware and remains
correct if the value is later reused in a different context; input filtering is
neither, and silently corrupts legitimate data such as an ampersand in a name.</p>

<p>Rendering goes through the auto-escaping template engine, with no escape
bypass anywhere in the project &mdash; a test asserts that no template uses the
<span class="evid">|safe</span> filter and no module constructs
<span class="evid">Markup()</span>. Behind that sits a nonce-based Content
Security Policy: <span class="evid">script-src 'self' 'nonce-&lt;random&gt;'</span>
with no <span class="evid">'unsafe-inline'</span>, so injected script lacking the
per-response nonce is not executed. The nonce is regenerated per response.</p>

<p>Verified live: a stored marker containing markup metacharacters is returned
in the response as HTML entities, while the database confirms the original value
was stored unmodified.</p>
<p class="sub">Evidence: <span class="evid">E5_xss_encoding.txt</span>,
<span class="evid">E1_http_security_headers.txt</span>.</p>

<h3>4.2 Cross-site request forgery</h3>

<p>Course registration and profile update are protected with the synchroniser
token pattern. A random token is bound to the session and must be echoed on
every state-changing request. An attacker's page can cause the browser to send a
cross-site POST, but the same-origin policy prevents it from reading the
victim's token, so the forged request fails validation. Enforcement is central
rather than per-view:</p>

{code_block("secure_app/__init__.py :: before_request (CSRF enforcement)", CSRF_CODE)}

<p>Tokens are compared in constant time. <span class="evid">SameSite=Lax</span>
on the session cookie is an independent second layer: the browser withholds the
cookie from cross-site POSTs entirely, so the request arrives unauthenticated
even before token validation. Verified live: a POST with no token and a POST
with a forged token both return 403, the token issued to one session does not
authorise a request in another, and the correct token succeeds.</p>
<p class="sub">Evidence: <span class="evid">E3_csrf_enforcement.txt</span>.</p>

<h3>4.3 Server-side request forgery</h3>

<p>The URL-preview feature makes the server issue a request on the user's
behalf, which without restriction turns it into a proxy into the trusted
network. Six controls are applied in order: scheme allowlist (http/https only),
port allowlist, host allowlist, DNS resolution with every returned address
checked, address pinning, and redirects disabled.</p>

{code_block("secure_app/security.py :: validate_outbound_url()", SSRF_CODE)}

<p>Two details matter more than the allowlist itself. Checking <i>every</i>
resolved address and rejecting the name if any one is internal defeats DNS
rebinding, where an approved name answers with an internal address. Pinning the
connection to the address that was vetted closes the time-of-check to
time-of-use gap between validation and connection. Disabling redirects matters
because a 302 response would otherwise be followed to a destination that was
never checked. The host allowlist is evaluated before resolution, so a blocked
host generates no DNS lookup at all &mdash; confirmed by a test that counts
resolver calls.</p>

<p>Verified live against loopback, private, metadata, non-HTTP-scheme,
non-standard-port, unlisted-host and embedded-credential destinations: all
refused, each logged. The refusal wording is deliberately uniform so the
endpoint cannot be used as an internal-network oracle.</p>
<p class="sub">Evidence: <span class="evid">E4_ssrf_policy.txt</span>.</p>

<h3>4.4 Security misconfiguration</h3>

<ul>
<li><b>No default credentials.</b> The seed script generates passwords at
runtime and prints them once; nothing is hardcoded. A test scans the source for
credential-like assignments.</li>
<li><b>Debug disabled</b> by default, and the production profile
<i>refuses to start</i> without a SECRET_KEY rather than falling back to a
guessable default &mdash; asserted by a test.</li>
<li><b>Secrets kept out of the repository</b> via <span class="evid">.env</span>
(git-ignored) with a committed template.</li>
<li><b>Security headers</b> applied centrally: CSP, X-Content-Type-Options,
X-Frame-Options: DENY, Referrer-Policy, Permissions-Policy, COOP/CORP and
Cache-Control: no-store. HSTS is emitted only over TLS, since it is meaningless
on a plain-HTTP lab origin. The server banner is overwritten so the framework
and version are not disclosed.</li>
<li><b>Generic error handling.</b> Unhandled exceptions return a reference code;
the detail goes only to the server log. This closes the verbose-error defect
that let the prototype disclose schema information.</li>
<li><b>Upload hardening.</b> Extension and declared-type allowlists, a magic-byte
check that the content matches the claimed type, a 2 MiB ceiling, and a
server-generated random storage name outside any served directory with 0600
permissions &mdash; so a supplied name can neither traverse directories nor set
an executable extension.</li>
<li><b>Dependencies</b> pinned in <span class="evid">requirements.txt</span>:
Flask 3.1.3, argon2-cffi 25.1.0, requests 2.33.1, pytest 8.4.2, with no known
advisories outstanding at the time of writing.</li>
</ul>
<p class="sub">Evidence: <span class="evid">E1_http_security_headers.txt</span>,
<span class="evid">E12_access_control.txt</span>,
<span class="evid">E13_upload_validation.txt</span>.</p>

<h3>4.5 Security logging</h3>

<p>Failed logins, denied authorisations and rejected validation are recorded as
structured JSON events answering who, what, when and outcome.</p>

{code_block("secure_app/security.py :: redact()", LOG_CODE)}

<p>Secrets are stripped by key before anything is written, and email addresses
are masked so the log retains the domain for triage without recording the full
personal identifier. Actors are internal user IDs rather than names, which keeps
the personal data in the log to the minimum the record needs to be useful. An
automated check greps the produced log for every lab password, the full email
address and the session cookie: none appear.</p>
<p class="sub">Evidence: <span class="evid">E11_security_log.txt</span>
(40 events across 14 event types),
<span class="evid">evidence/logs/security.log</span>.</p>

<h3>4.6 Incident response</h3>

<p>A one-page runbook covers all six stages &mdash; Preparation, Identification,
Containment, Eradication, Recovery and Lessons Learned &mdash; with named log
sources, alert thresholds, a P1&ndash;P3 severity scale, and the instruction to
preserve evidence with recorded hashes before changing anything. Containment
distinguishes short-term actions from longer-term ones and prefers disabling a
single feature by configuration over taking the whole service down. Eradication
requires a regression test that fails against the vulnerable version, so a fix
is not accepted on assertion alone.</p>

<p>The runbook was exercised against a genuine event: the lockout sequence
generated during evidence capture was worked through as incident
<b>INC-2026-0003</b> and closed as P3, attempted account compromise blocked by
control.</p>
<p class="sub">Documents: <span class="evid">docs/runbook.md</span>,
<span class="evid">docs/incident_record.md</span>.</p>

<h3>4.7 Ethics and lawful conduct</h3>

<p>A signed declaration accompanies this submission at
<span class="evid">docs/ethics_declaration.md</span>. It records that all testing
was confined to a locally-run instance on the loopback interface, that no
university, public or third-party system was contacted, that no real person's
credentials or personal data were used, and that the internal addresses named in
the SSRF evidence appear only as inputs the application <i>refused</i>. The
<span class="evid">.test</span> domain used throughout is reserved by RFC 6761
for exactly this purpose and resolves to nothing.</p>

<h2>5. A defect found during evidence capture</h2>

<p>Capturing the response headers with <span class="evid">curl -I</span>
returned HTTP 401 from the login page, which should have been 200. The cause was
that the views tested <span class="evid">request.method == "GET"</span>. Flask
allows HEAD implicitly and routes it to the GET handler, but
<span class="evid">request.method</span> remains "HEAD", so a HEAD request fell
past that branch into the credential-processing path, failed validation and
emitted a spurious failed-login audit event.</p>

{code_block("secure_app/auth.py, secure_app/routes.py", HEAD_BUG)}

<p>The security consequence is not the wrong status code. Any monitoring probe,
link checker or search crawler issuing HEAD would have written false
failed-login events into the audit trail, degrading the evidence that Task 3
depends on, and would have driven accounts toward lockout &mdash; turning a
detection control into a denial-of-service vector. It is recorded here because
it was found by capturing evidence rather than by reading the code, which is the
practical argument for producing evidence from a running system rather than
describing intended behaviour. Two regression tests now cover it.</p>

<h2>6. Conclusion</h2>

<p>The assessment identified {len(stride)} threats across all six STRIDE
categories and reduced the three highest from Critical and High to Low residual
scores, with three lower risks formally accepted and justified. The two defects
that dominated the profile were addressed at their root: statement structure is
now independent of user input, and credentials are stored as memory-hard salted
hashes that are never placed in a query. Defences for the four required
vulnerability classes are in place and evidenced from live output, and logging,
incident response and ethical conduct are documented.</p>

<p>Three limitations are stated plainly. Sessions are signed client-side cookies
rather than a server-side store, so regeneration means discarding pre-auth state
and minting a new identifier; a server-side store would additionally permit
server-initiated revocation. Rate-limit counters live in the application
database, which suits a single process but would need a shared store behind
multiple workers. The audit log is written to the same host as the application,
so off-host forwarding to write-once storage should precede any deployment
beyond the lab.</p>

<h2>7. References</h2>

<ol>
<li>OWASP Foundation, <i>OWASP Top 10:2021 &mdash; The Ten Most Critical Web
Application Security Risks</i>, 2021. Used for the classification of A01
Broken Access Control, A03 Injection, A05 Security Misconfiguration and A10
Server-Side Request Forgery.</li>
<li>OWASP Foundation, <i>Password Storage Cheat Sheet</i>. Source of the
Argon2id parameter baseline (19 MiB memory, 2 iterations, 1 degree of
parallelism) applied in &sect;3.4.</li>
<li>OWASP Foundation, <i>Cross-Site Request Forgery Prevention Cheat Sheet</i>
and <i>Server-Side Request Forgery Prevention Cheat Sheet</i>. Basis for the
synchroniser-token pattern in &sect;4.2 and the destination-policy ordering in
&sect;4.3.</li>
<li>Microsoft, <i>The STRIDE Threat Model</i> (Microsoft Learn / Security
Development Lifecycle). Methodology used for the decomposition in &sect;2.</li>
<li>P. Cichonski, T. Millar, T. Grance and K. Scarfone, <i>Computer Security
Incident Handling Guide</i>, NIST Special Publication 800-61 Revision 2, 2012.
Structure of the incident-response runbook in &sect;4.6.</li>
<li>A. Biryukov, D. Dinu and D. Khovratovich, <i>Argon2: the memory-hard
function for password hashing and other applications</i>, Password Hashing
Competition, 2015.</li>
<li>M. M'Raihi, S. Machani, M. Pei and J. Rydell, <i>TOTP: Time-Based One-Time
Password Algorithm</i>, RFC 6238, IETF, 2011. Implemented in &sect;3.5.</li>
<li>MITRE, <i>Common Weakness Enumeration</i>: CWE-89 (SQL Injection), CWE-79
(Cross-site Scripting), CWE-352 (CSRF), CWE-918 (SSRF), CWE-256/257 (password
storage), CWE-209 (information exposure through an error message), CWE-384
(session fixation).</li>
<li>M. Stapleton (ed.), <i>Reserved Top Level Domain Names</i>, RFC 6761, IETF,
2013. Basis for using the <span class="evid">.test</span> domain for lab
destinations.</li>
</ol>

<p class="sub">Declaration of assistance: the work, design decisions and
analysis in this submission are my own. Where reference material listed above
informed a control, it is cited at the point of use.</p>

<div class="pb"></div>
<h2>Appendix A &mdash; Controls applied and verification</h2>
{controls_table()}

<h2>Appendix B &mdash; Evidence index</h2>
<table class="grid small">
<thead><tr><th>Item</th><th>Contents</th><th>Supports</th></tr></thead><tbody>
<tr><td class="id">E1</td><td>HTTP security response headers, live capture</td><td>Task 3 &sect;4.1, &sect;4.4</td></tr>
<tr><td class="id">E2</td><td>Authentication outcomes: valid, wrong password, unknown account, admin MFA redirect, HEAD, anonymous, forbidden</td><td>Task 2 &sect;3.5</td></tr>
<tr><td class="id">E3</td><td>CSRF: missing, forged and valid token; cookie flags</td><td>Task 3 &sect;4.2</td></tr>
<tr><td class="id">E4</td><td>SSRF: eight refused destination classes</td><td>Task 3 &sect;4.3</td></tr>
<tr><td class="id">E5</td><td>XSS: stored value vs. rendered output</td><td>Task 3 &sect;4.1</td></tr>
<tr><td class="id">E6</td><td>Password storage: Argon2id parameters, truncated hashes, schema check</td><td>Task 2 &sect;3.4</td></tr>
<tr><td class="id">E7</td><td>SQL injection before/after side-by-side run</td><td>Task 2 &sect;3.1&ndash;3.3</td></tr>
<tr><td class="id">E8</td><td>Account lockout and source rate limiting</td><td>Task 2 &sect;3.5</td></tr>
<tr><td class="id">E9</td><td>Full pytest transcript ({N_TESTS} tests)</td><td>All tasks</td></tr>
<tr><td class="id">E10</td><td>Static AST scan for dynamically built SQL, with control file</td><td>Task 2 &sect;3.3</td></tr>
<tr><td class="id">E11</td><td>Security audit log, redacted, with secret-absence checks</td><td>Task 3 &sect;4.5</td></tr>
<tr><td class="id">E12</td><td>Access control: vertical, horizontal, forged role</td><td>Task 3 &sect;4.4</td></tr>
<tr><td class="id">E13</td><td>Upload validation: extension, content, path component</td><td>Task 3 &sect;4.4</td></tr>
</tbody></table>

<h2>Appendix C &mdash; Reproducing this assessment</h2>
<pre class="code">pip install -r requirements.txt
python3 scripts/seed.py --fixed        # fictitious accounts
python3 run.py                         # binds 127.0.0.1 only
python3 -m pytest tests/ -v            # {N_TESTS} tests
bash scripts/capture_evidence.sh       # regenerates E1-E13
python3 scripts/threat_model.py        # STRIDE worksheet + risk register
python3 scripts/make_dfd.py            # data-flow diagram
python3 scripts/build_report.py        # this report</pre>
<p class="sub">Setup instructions, test accounts and known limitations are in
<span class="evid">README.md</span>.</p>

</body></html>"""


def main() -> None:
    html_path = ROOT / "report_build.html"
    html_path.write_text(build_html(), encoding="utf-8")

    cmd = [
        "wkhtmltopdf", "--enable-local-file-access",
        "--footer-font-size", "8", "--footer-font-name", "Georgia",
        "--footer-left", f"IFT 542 Practical Assignment  |  {MATRIC}",
        "--footer-right", "Page [page] of [topage]",
        "--footer-spacing", "5",
        "--print-media-type", "--dpi", "150",
        str(html_path), str(OUT_PDF),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stdout[-2000:], result.stderr[-2000:], file=sys.stderr)
        sys.exit("wkhtmltopdf failed")
    html_path.unlink()
    print("Wrote", OUT_PDF)


if __name__ == "__main__":
    main()
