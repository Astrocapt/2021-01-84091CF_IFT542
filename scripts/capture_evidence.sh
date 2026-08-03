#!/usr/bin/env bash
# ===========================================================================
# scripts/capture_evidence.sh
# ===========================================================================
# Regenerates the complete evidence set (E1-E13) referenced by the report.
#
# Every request in this script targets 127.0.0.1 only. No external host is
# contacted at any point, and all accounts are fictitious lab accounts.
#
# Usage (from the repository root):
#     bash scripts/capture_evidence.sh
#
# The script seeds a fresh database, starts the application on loopback,
# drives it with curl, writes evidence/captures/E*.txt, and stops the server.
# ===========================================================================
set -u

cd "$(dirname "$0")/.."
CAP=evidence/captures
mkdir -p "$CAP" evidence/logs
STAMP=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
BASE=http://127.0.0.1:5000

echo "[*] Seeding a fresh database with fictitious data ..."
rm -f evidence/logs/security.log
python3 scripts/seed.py --fixed > /tmp/seed_out.txt 2>&1

export SECRET_KEY=$(python3 -c "import os;print(os.urandom(32).hex())")
echo "[*] Starting the application on 127.0.0.1:5000 ..."
python3 run.py > /tmp/server.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
sleep 4

if ! curl -s -o /dev/null "$BASE/login"; then
  echo "[!] Server did not start. See /tmp/server.log"; exit 1
fi

# Fetch the anti-CSRF token the server issued for a given cookie jar.
tok(){ curl -s -b "$1" -c "$1" "$BASE$2" \
       | grep -o 'name="csrf_token" value="[^"]*"' | head -1 | cut -d'"' -f4; }
Q(){ curl -s -o /dev/null "$@"; }

# ---------------------------------------------------------------- E1 -------
echo "[*] E1  security headers"
{
echo "EVIDENCE E1 - HTTP security response headers"
echo "Captured: $STAMP    Target: $BASE (localhost lab only)"
echo "Command:  curl -sS -D - -o /dev/null $BASE/login"
echo "=========================================================================="
curl -sS -D - -o /dev/null "$BASE/login"
echo
echo "Strict-Transport-Security is emitted only over TLS and is therefore absent"
echo "on this plain-HTTP lab origin by design (secure_app/__init__.py)."
echo "The Server banner is overwritten so the framework/version is not disclosed."
} > "$CAP/E1_http_security_headers.txt"

# ---------------------------------------------------------------- E2 -------
echo "[*] E2  authentication outcomes"
{
echo "EVIDENCE E2 - Authentication outcomes over HTTP"
echo "Captured: $STAMP    Fictitious lab accounts only"
echo "=========================================================================="
rm -f /tmp/j1.txt; T=$(tok /tmp/j1.txt /login)
echo "[1] Valid credentials -> expect 302 to /dashboard"
curl -s -b /tmp/j1.txt -c /tmp/j1.txt -o /dev/null -w "    HTTP %{http_code}  Location: %{redirect_url}\n" \
  -d "email=student.one@lab.test" -d "password=LabStudent#2026a" -d "csrf_token=$T" "$BASE/login"
echo; rm -f /tmp/j2.txt; T=$(tok /tmp/j2.txt /login)
echo "[2] Wrong password -> expect 401, generic message"
curl -s -b /tmp/j2.txt -c /tmp/j2.txt -o /tmp/bad.html -w "    HTTP %{http_code}\n" \
  -d "email=student.one@lab.test" -d "password=DefinitelyWrong#2026" -d "csrf_token=$T" "$BASE/login"
echo "    Message: $(grep -o 'Invalid credentials[^<]*' /tmp/bad.html | head -1)"
echo; rm -f /tmp/j3.txt; T=$(tok /tmp/j3.txt /login)
echo "[3] Unknown account -> expect the SAME 401 and message (no enumeration)"
curl -s -b /tmp/j3.txt -c /tmp/j3.txt -o /tmp/unk.html -w "    HTTP %{http_code}\n" \
  -d "email=does.not.exist@lab.test" -d "password=DefinitelyWrong#2026" -d "csrf_token=$T" "$BASE/login"
echo "    Message: $(grep -o 'Invalid credentials[^<]*' /tmp/unk.html | head -1)"
echo; rm -f /tmp/j4.txt; T=$(tok /tmp/j4.txt /login)
echo "[4] Admin account -> expect 302 to /login/mfa (second factor required)"
curl -s -b /tmp/j4.txt -c /tmp/j4.txt -o /dev/null -w "    HTTP %{http_code}  Location: %{redirect_url}\n" \
  -d "email=registrar@lab.test" -d "password=LabRegistrar#2026" -d "csrf_token=$T" "$BASE/login"
echo; echo "[5] HEAD /login -> expect 200, and no failed-login event (regression check)"
curl -sS -I -o /dev/null -w "    HTTP %{http_code}\n" "$BASE/login"
echo; echo "[6] Anonymous request for /dashboard -> expect 302 to /login"
curl -s -o /dev/null -w "    HTTP %{http_code}  Location: %{redirect_url}\n" "$BASE/dashboard"
echo; echo "[7] Student session requesting /admin -> expect 403"
curl -s -b /tmp/j1.txt -o /dev/null -w "    HTTP %{http_code}\n" "$BASE/admin"
} > "$CAP/E2_authentication_outcomes.txt"

# ---------------------------------------------------------------- E3 -------
echo "[*] E3  CSRF enforcement"
{
echo "EVIDENCE E3 - Anti-CSRF token enforcement"
echo "Captured: $STAMP"
echo "=========================================================================="
echo "[1] Authenticated POST with NO token -> expect 403"
curl -s -b /tmp/j1.txt -o /dev/null -w "    HTTP %{http_code}\n" -d "course_id=1" "$BASE/courses/register"
echo; echo "[2] Authenticated POST with a FORGED token -> expect 403"
curl -s -b /tmp/j1.txt -o /dev/null -w "    HTTP %{http_code}\n" -d "course_id=1" \
  -d "csrf_token=forged-value-never-issued" "$BASE/courses/register"
echo; echo "[3] Authenticated POST with the ISSUED token -> expect 302 (accepted)"
T=$(tok /tmp/j1.txt /courses)
curl -s -b /tmp/j1.txt -c /tmp/j1.txt -o /dev/null -w "    HTTP %{http_code}  Location: %{redirect_url}\n" \
  -d "course_id=1" -d "csrf_token=$T" "$BASE/courses/register"
echo; echo "[4] Session cookie flags as issued by the server:"
curl -sS -D - -o /dev/null "$BASE/login" | grep -i "^set-cookie" | sed 's/^/    /'
} > "$CAP/E3_csrf_enforcement.txt"

# ---------------------------------------------------------------- E4 -------
echo "[*] E4  SSRF destination policy"
{
echo "EVIDENCE E4 - SSRF destination policy (localhost only)"
echo "Captured: $STAMP"
echo "All targets below are loopback / private / metadata addresses. No request"
echo "leaves the host: the guard refuses before any socket is opened."
echo "=========================================================================="
for U in "http://127.0.0.1:5000/admin" "http://localhost/" "http://169.254.169.254/latest/meta-data/" \
         "http://10.0.0.5/internal" "file:///etc/passwd" "http://docs.futminna.test:8080/x" \
         "https://unlisted.example.net/doc.pdf" "https://docs.futminna.test@127.0.0.1/"; do
  T=$(tok /tmp/j1.txt /documents/preview)
  CODE=$(curl -s -b /tmp/j1.txt -c /tmp/j1.txt -o /tmp/p.html -w "%{http_code}" \
        --data-urlencode "url=$U" -d "csrf_token=$T" "$BASE/documents/preview")
  printf "    %-45s -> HTTP %s  %s\n" "$U" "$CODE" "$(grep -o 'not permitted' /tmp/p.html | head -1)"
done
} > "$CAP/E4_ssrf_policy.txt"

# ---------------------------------------------------------------- E5 -------
echo "[*] E5  XSS output encoding"
{
echo "EVIDENCE E5 - XSS output encoding"
echo "Captured: $STAMP"
echo "A benign marker containing markup metacharacters is stored in the profile"
echo "bio field, then the rendered dashboard is inspected."
echo "=========================================================================="
T=$(tok /tmp/j1.txt /profile)
Q -b /tmp/j1.txt -c /tmp/j1.txt -d "department=Information Technology" -d "level=500" \
  -d "phone=+2348000000001" --data-urlencode 'bio=<script>marker</script>' \
  -d "csrf_token=$T" "$BASE/profile"
echo "Stored value (read back from the database, unmodified):"
python3 -c "
import sqlite3
print('   ', sqlite3.connect('instance/registration.sqlite3').execute(
      'SELECT bio FROM profiles WHERE user_id=1').fetchone()[0])"
echo
echo "As rendered in the HTML response (grep of the bio element):"
curl -s -b /tmp/j1.txt "$BASE/dashboard" | grep -o 'id="bio-field">[^<]*&[^<]*' | sed 's/^/    /'
echo
echo "The angle brackets were converted to entities, so the browser parses the"
echo "value as text. The CSP provides the second, independent barrier."
} > "$CAP/E5_xss_encoding.txt"

# ---------------------------------------------------------------- E6 -------
echo "[*] E6  password storage"
python3 scripts/db_evidence.py > "$CAP/E6_password_storage.txt"

# ---------------------------------------------------------------- E7 -------
echo "[*] E7  SQL injection before/after"
python3 scripts/demo_sqli.py > "$CAP/E7_sqli_before_after.txt"

# ---------------------------------------------------------------- E8 -------
echo "[*] E8  lockout and rate limiting"
{
echo "EVIDENCE E8 - Account lockout and source rate limiting"
echo "Captured: $STAMP"
echo "Target: 127.0.0.1:5000, fictitious account student.two@lab.test"
echo "Policy: lock after 5 account failures for 15 minutes; throttle a source"
echo "        after 20 failures in a 15-minute window."
echo "======================================================================"
echo; echo "Repeated wrong-password submissions for one account:"
for i in $(seq 1 7); do
  rm -f /tmp/lk.txt; T=$(tok /tmp/lk.txt /login)
  C=$(curl -s -b /tmp/lk.txt -c /tmp/lk.txt -o /tmp/r.html -w "%{http_code}" \
     -d "email=student.two@lab.test" -d "password=WrongPassword#$i" -d "csrf_token=$T" "$BASE/login")
  printf "  attempt %d -> HTTP %s   %s\n" "$i" "$C" \
    "$(grep -o 'Invalid credentials\|Too many attempts' /tmp/r.html | head -1)"
done
echo; echo "Account state recorded in the database after the run:"
python3 -c "
import sqlite3
r=sqlite3.connect('instance/registration.sqlite3').execute(
  'SELECT failed_attempts, locked_until FROM users WHERE email=?',
  ('student.two@lab.test',)).fetchone()
print(f'    failed_attempts = {r[0]}')
print(f'    locked_until    = {r[1]}  (UTC, temporary)')
print('    note: the counter stops at the threshold because later attempts are')
print('          refused by the lock before the credential check is reached.')"
echo; echo "Now the CORRECT password, while the lock is in force:"
rm -f /tmp/lk.txt; T=$(tok /tmp/lk.txt /login)
C=$(curl -s -b /tmp/lk.txt -c /tmp/lk.txt -o /tmp/r.html -w "%{http_code}" \
   -d "email=student.two@lab.test" -d "password=LabStudent#2026b" -d "csrf_token=$T" "$BASE/login")
echo "    HTTP $C   $(grep -o 'Invalid credentials[^<]*' /tmp/r.html | head -1)"
echo
echo "  The refusal is worded identically to an ordinary failure, so the"
echo "  response does not tell an attacker that the account is locked."
echo; echo "Unaffected account still authenticates normally (lockout is per-account):"
rm -f /tmp/ok.txt; T=$(tok /tmp/ok.txt /login)
curl -s -b /tmp/ok.txt -c /tmp/ok.txt -o /dev/null -w "    HTTP %{http_code}  Location: %{redirect_url}\n" \
  -d "email=student.one@lab.test" -d "password=LabStudent#2026a" -d "csrf_token=$T" "$BASE/login"
} > "$CAP/E8_lockout_and_ratelimit.txt"

# ---------------------------------------------------------------- E12 ------
echo "[*] E12 access control"
rm -f /tmp/s.txt; T=$(tok /tmp/s.txt /login)
Q -b /tmp/s.txt -c /tmp/s.txt -d "email=student.one@lab.test" -d "password=LabStudent#2026a" -d "csrf_token=$T" "$BASE/login"
{
echo "EVIDENCE E12 - Access control (vertical and horizontal)"
echo "Captured: $STAMP    Session: student.one@lab.test (role=student)"
echo "======================================================================"
echo; echo "[1] Student session requests the administrative area -> expect 403"
curl -s -b /tmp/s.txt -o /dev/null -w "    GET /admin                              HTTP %{http_code}\n" "$BASE/admin"
echo; echo "[2] Same request, but with a forged role in a header and query string."
echo "    Authorisation reads the role from the server-side session record, so"
echo "    client-supplied role data has no effect -> expect 403"
curl -s -b /tmp/s.txt -H "X-Role: admin" -o /dev/null \
  -w "    GET /admin?role=admin (X-Role: admin)   HTTP %{http_code}\n" "$BASE/admin?role=admin"
echo; echo "[3] Student attempts a privileged write -> expect 403"
T=$(tok /tmp/s.txt /courses)
curl -s -b /tmp/s.txt -c /tmp/s.txt -o /dev/null -w "    POST /admin/courses                     HTTP %{http_code}\n" \
  -d "code=XXX 999" -d "title=Injected Course" -d "units=3" -d "csrf_token=$T" "$BASE/admin/courses"
echo; echo "[4] Anonymous session requests a protected page -> expect 302 to /login"
curl -s -o /dev/null -w "    GET /dashboard                          HTTP %{http_code} -> %{redirect_url}\n" "$BASE/dashboard"
echo; echo "[5] Confirm no course was created by step [3]:"
python3 -c "
import sqlite3
n=sqlite3.connect('instance/registration.sqlite3').execute(
  \"SELECT COUNT(*) FROM courses WHERE code='XXX 999'\").fetchone()[0]
print(f'    courses matching the attempted insert: {n}  (' + ('none created - PASS' if n==0 else 'FAIL') + ')')"
echo; echo "Each denial is recorded as an authz.denied audit event (see E11)."
} > "$CAP/E12_access_control.txt"

# ---------------------------------------------------------------- E13 ------
echo "[*] E13 upload validation"
printf '#!/bin/sh\necho lab test\n' > /tmp/notes.sh
echo "not actually a pdf, just text" > /tmp/fake.pdf
printf '%%PDF-1.4\n%% fictitious lab document\n' > /tmp/real.pdf
u(){ T=$(tok /tmp/s.txt /dashboard)
     curl -s -b /tmp/s.txt -c /tmp/s.txt -o /tmp/up.html -L \
       -F "csrf_token=$T" -F "document=@$1;filename=$2" "$BASE/documents/upload"
     grep -o 'not accepted\|do not match\|Document uploaded\|too large' /tmp/up.html | head -1; }
{
echo "EVIDENCE E13 - Upload validation"
echo "Captured: $STAMP"
echo "Policy: extension allowlist, declared-type allowlist, magic-byte check,"
echo "        2 MiB ceiling, server-generated storage name outside any served path."
echo "======================================================================"
echo
printf "    %-42s -> %s\n" "notes.sh (disallowed extension)"     "$(u /tmp/notes.sh notes.sh)"
printf "    %-42s -> %s\n" "fake.pdf (content contradicts type)" "$(u /tmp/fake.pdf report.pdf)"
printf "    %-42s -> %s\n" "real.pdf named '../../handbook.pdf'" "$(u /tmp/real.pdf ../../handbook.pdf)"
echo; echo "Stored record for the accepted file:"
python3 -c "
import sqlite3
r=sqlite3.connect('instance/registration.sqlite3').execute(
 'SELECT original_name, stored_name, content_type, size_bytes FROM documents ORDER BY id DESC LIMIT 1').fetchone()
if r:
    print(f'    original_name : {r[0]}   (path component stripped)')
    print(f'    stored_name   : {r[1]}   (server-generated, random)')
    print(f'    content_type  : {r[2]}   (from magic bytes, not trusted from the client)')
    print(f'    size_bytes    : {r[3]}')"
echo; echo "Files on disk in the upload directory (no original names, no executable"
echo "extensions, and the directory is not served by the web application):"
ls -l instance/uploads | tail -n +2 | awk '{printf "    %s  %s\n", $1, $9}'
} > "$CAP/E13_upload_validation.txt"

# ---------------------------------------------------------------- E11 ------
echo "[*] E11 security log"
T=$(tok /tmp/s.txt /documents/preview)
Q -b /tmp/s.txt -c /tmp/s.txt --data-urlencode "url=http://169.254.169.254/latest/meta-data/" \
  -d "csrf_token=$T" "$BASE/documents/preview"
Q -b /tmp/s.txt -d "course_id=1" "$BASE/courses/register"
T=$(tok /tmp/s.txt /profile)
Q -b /tmp/s.txt -c /tmp/s.txt --data-urlencode "department=$(python3 -c 'print("A"*300)')" \
  -d "level=500" -d "phone=" -d "bio=" -d "csrf_token=$T" "$BASE/profile"
T=$(tok /tmp/s.txt /dashboard)
Q -b /tmp/s.txt -c /tmp/s.txt -d "csrf_token=$T" "$BASE/logout"
bash scripts/format_log_evidence.sh > "$CAP/E11_security_log.txt"

# ---------------------------------------------------------------- E9/E10 ---
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; trap - EXIT

echo "[*] E9  test suite"
{
echo "EVIDENCE E9 - Automated test suite"
echo "Captured: $STAMP"
echo "Command:  python -m pytest tests/ -v"
echo "Scope: every test runs against a throwaway database of fictitious records."
echo "       No test contacts any host other than the in-process test client."
echo "======================================================================"
echo
python3 -m pytest tests/ -v --tb=short -p no:cacheprovider 2>&1
} > "$CAP/E9_test_results.txt"

echo "[*] E10 static SQL scan"
bash scripts/format_scan_evidence.sh > "$CAP/E10_static_sql_scan.txt"

echo
echo "[+] Evidence regenerated in $CAP:"
ls -1 "$CAP" | sed 's/^/    /'
