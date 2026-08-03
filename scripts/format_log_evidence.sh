#!/usr/bin/env bash
# Formats evidence/logs/security.log into the annotated E11 evidence file.
cd "$(dirname "$0")/.."
echo "EVIDENCE E11 - Security audit log (redacted extract)"
echo "Captured: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "File: evidence/logs/security.log  (JSON Lines, one event per line)"
echo "Fictitious lab accounts. Source addresses are loopback."
echo "======================================================================"
echo
echo "EVENT SUMMARY FOR THE CAPTURE SESSION"
echo
python3 - << 'PY'
import json, collections
events = [json.loads(l) for l in open("evidence/logs/security.log") if l.strip()]
counts = collections.Counter((e["event"], e["outcome"]) for e in events)
print(f"  {'event':<22}{'outcome':<10}{'count':>6}")
print("  " + "-" * 38)
for (event, outcome), n in sorted(counts.items()):
    print(f"  {event:<22}{outcome:<10}{n:>6}")
print("  " + "-" * 38)
print(f"  {'TOTAL':<32}{len(events):>6}")
PY
echo
echo "======================================================================"
echo "DETAILED TIMELINE (final 15 events of the session)"
echo
python3 - << 'PY'
import json
labels = {
 "auth.login":"login attempt","auth.lockout":"account lockout engaged",
 "auth.mfa":"second-factor verification","auth.mfa_challenge":"second factor requested",
 "authz.denied":"authorisation denied","csrf.rejected":"CSRF token rejected",
 "ssrf.blocked":"outbound destination blocked","ssrf.allowed":"outbound fetch permitted",
 "validation.rejected":"input validation rejected","enrolment.create":"course registered",
 "auth.logout":"session ended","upload.accepted":"document accepted",
 "upload.rejected":"document rejected","profile.update":"profile updated",
}
events = [json.loads(l) for l in open("evidence/logs/security.log") if l.strip()]
start = max(0, len(events) - 15)
for i, e in enumerate(events[start:], start + 1):
    print(f"  {i:>2}. {e['ts']}  {labels.get(e['event'], e['event'])}")
    print(f"      event={e['event']}  outcome={e['outcome']}  actor={e['actor']}"
          f"  subject={e['subject']}  source={e['source_ip']}")
    if e["detail"]:
        print(f"      detail={e['detail']}")
PY
echo
echo "======================================================================"
echo "RAW FORMAT (first three lines, exactly as written to disk)"
echo
head -3 evidence/logs/security.log | sed 's/^/  /'
echo
echo "======================================================================"
echo "WHAT THE RECORD ANSWERS"
echo "  who   : actor (internal user id, not a name or address)"
echo "  what  : event + subject + outcome"
echo "  when  : ts, ISO-8601 with UTC offset"
echo "  where : source_ip"
echo
echo "WHAT IS DELIBERATELY ABSENT"
echo "  * no password, OTP code, session cookie, CSRF token or MFA secret"
echo "  * email addresses are masked (r***r@lab.test), keeping the domain for"
echo "    triage while not writing the full personal identifier to the log"
echo "  * no full request body and no stack trace"
echo
echo "AUTOMATED CHECK - searching the log for values that must never appear:"
python3 - << 'PY'
raw = open("evidence/logs/security.log").read()
checks = {
  "student password": "LabStudent#2026a",
  "registrar password": "LabRegistrar#2026",
  "wrong-password guess": "WrongPassword#1",
  "full email address": "registrar@lab.test",
  "session cookie name/value": "sr_session=",
}
for label, needle in checks.items():
    print(f"  {label:<28} {'FOUND - FAIL' if needle in raw else 'absent - PASS'}")
PY
