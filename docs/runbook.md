# Incident Response Runbook — Student Registration Web Application

**System:** Student Registration Web Application (localhost lab build)
**Owner:** Application Security Engineer (junior), Department of Information Technology
**Scope:** Authentication compromise, injection, XSS/CSRF, SSRF and access-control incidents affecting this application only
**Version:** 1.0 · IFT 542 Practical Assignment

---

## 1. Preparation

| Item | Detail |
|---|---|
| Contacts | Departmental IT lead (primary), system owner, data-protection contact, Head of Department for any incident involving student personal data |
| Log sources | `evidence/logs/security.log` (JSON lines), `audit_log` table, `login_attempts` table, reverse-proxy access log |
| Baseline | Known-good commit hash, `migrations/001_schema.sql`, dependency lock file, last verified test run |
| Access | Break-glass administrator credential held offline; administrator accounts require a second factor |
| Readiness checks | Full test suite green before each release; log write path verified weekly; restore from backup rehearsed each semester |
| Thresholds | ≥20 failed logins from one address in 15 minutes, any `authz.denied` on an administrative route, any `ssrf.blocked` event, any `csrf.rejected` burst |

## 2. Identification

1. Confirm the alert is genuine by reading the raw events, not the alert summary alone.
2. Filter the audit log by event type and time window:
   `grep '"event":"auth.login"' evidence/logs/security.log | grep '"outcome":"failure"'`
3. Establish **who** (actor, masked identifier, source address), **what** (event and object), **when** (first and last timestamp) and **outcome**.
4. Classify severity: **P1** confirmed data disclosure or administrative compromise · **P2** account compromise, no privileged access · **P3** blocked or attempted only.
5. Open an incident record and start a timestamped action log. Record facts and their source; keep inference separate from observation.

## 3. Containment

*Short term (minutes):*
- Lock or disable the affected accounts; invalidate their sessions by rotating `SECRET_KEY`, which discards every issued session cookie.
- Block the offending source address at the proxy; tighten the rate-limit threshold if the pattern is distributed.
- Disable the affected feature by configuration where the flaw is in one endpoint (for example empty the URL-preview allowlist) rather than taking the whole service down.

*Longer term (hours):*
- Preserve evidence **before** changing anything: copy the database file, the log files and the upload directory to read-only storage and record a SHA-256 of each.
- Keep the service available to unaffected users if it can be done safely.

## 4. Eradication

1. Identify the root cause from the evidence, not from assumption. Reproduce it in the isolated lab build.
2. Correct the defect at its source: a parameterised statement, a missing authorisation check, a validation rule, a dependency upgrade.
3. Search for the same pattern elsewhere in the codebase before closing.
4. Remove any persistence the attacker established: injected profile content, uploaded files, added accounts or altered roles.
5. Rotate every secret that could have been exposed: signing key, database credentials, API keys, and force a password reset for affected accounts.
6. Add a regression test that fails against the vulnerable version and passes against the fix.

## 5. Recovery

1. Restore data from the last known-good backup only where integrity is in doubt; prefer targeted correction over wholesale restore.
2. Redeploy from a verified commit with the full test suite passing.
3. Return the service to normal in stages, monitoring the audit log at increased attention for at least 72 hours.
4. Confirm the specific attack path is closed by re-running the relevant tests and evidence captures.
5. Restore normal rate-limit and lockout thresholds once the elevated activity has stopped.
6. Notify affected students and the data-protection contact where personal data was disclosed, within the timeframe the applicable policy requires.

## 6. Lessons Learned

- Hold a review within five working days, with the record circulated beforehand.
- Produce a written timeline: first malicious action, first detection, containment, eradication, recovery. Measure time-to-detect and time-to-contain.
- Ask what allowed the defect to reach production and what allowed it to go unnoticed; these usually have different answers and need different fixes.
- Record actions with a named owner and a due date; track them to closure.
- Feed the finding back into the threat model and the risk register, adjusting likelihood scores where the incident shows the original estimate was wrong.
- Keep the review blameless. The aim is a system that fails less often, not an individual to hold responsible.

---

*Prepared for the IFT 542 practical assignment. All testing described in this runbook is performed against the isolated localhost lab instance using fictitious data.*
