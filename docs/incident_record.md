# Incident Record INC-2026-0003

**Classification:** P3 — attempted account compromise, blocked by control
**Status:** Closed
**Detected:** 2026-08-03 03:09:53 UTC
**Closed:** 2026-08-03 03:25 UTC
**Handler:** Abayomi Favour T. (junior application-security engineer)
**System:** Student Registration Web Application, localhost lab instance (127.0.0.1:5000)

> This record documents activity generated during authorised testing of the isolated lab build. The "attacker" is the assignment's own evidence-capture script, `scripts/capture_evidence.sh`, run against the loopback interface with fictitious accounts. No third-party or institutional system was involved at any point.

---

## 1. Summary

A sustained run of failed authentication attempts was directed at a single student account from one source address. The account-lockout control engaged on the fifth consecutive failure and refused all subsequent attempts, including one that presented the correct password. No session was established, no data was read or altered, and no privilege was gained.

## 2. Detection

Detected by the audit log threshold defined in the runbook (§1): five or more failed logins for one account within a short window.

Triggering event, taken verbatim from `evidence/logs/security.log`:

```json
{"ts":"2026-08-03T03:09:53+00:00","event":"auth.lockout","outcome":"denied","actor":"2","subject":"login","source_ip":"127.0.0.1","detail":{"email":"s***o@lab.test","attempts":5}}
```

The record carries who (actor `2`, masked identifier), what (`auth.lockout`), when (ISO-8601 UTC) and outcome (`denied`). It contains no password, session identifier or token. The e-mail is masked to its first and last local-part characters.

## 3. Timeline

| Time (UTC) | Event | Source |
|---|---|---|
| 02:48:08 | First failed sign-in for the target account | `auth.login` / failure |
| 02:48:08–02:48:09 | Four further consecutive failures, same account, same address | `auth.login` / failure ×4 |
| 02:48:09 | Threshold reached; account locked for 15 minutes | `auth.lockout` / denied |
| 02:48:09 | Attempt with the **correct** password refused while lock in force | `auth.login` / denied |
| 02:48:09 | Second refusal under the same lock | `auth.login` / denied |
| 02:50 | Log reviewed; source confirmed as the loopback interface | Analyst |
| 03:26 | Reviewed and closed; no further action required | Analyst |

Time to detect: under one second (automatic). Time to contain: under one second (automatic).

## 4. Impact assessment

| Question | Finding |
|---|---|
| Was any session established? | No. `auth.login`/`success` does not appear for the target account. |
| Was any data read or modified? | No. No `profile.update`, `enrolment.*` or `course.*` event for that actor. |
| Was privilege obtained? | No. The account holds the `student` role; three `authz.denied` events show administrative routes refused. |
| Was personal data disclosed? | No. Responses carried the generic failure message only. |
| Were credentials exposed? | No. Stored values are Argon2id hashes; the attempt log records no credential material. |

## 5. Response actions taken

1. **Containment** — automatic. Lockout engaged at the fifth failure; per-source limiting remained available had the pattern widened to other accounts.
2. **Evidence preservation** — the log file and the SQLite database were copied to read-only storage before any further testing; the `login_attempts` rows for the window were retained.
3. **Eradication** — none required. No defect was exploited; the control performed as designed.
4. **Recovery** — the lock was allowed to expire on its own 15-minute schedule rather than being cleared manually, so the account owner's normal recovery path was exercised.
5. **Verification** — `tests/test_auth.py::test_account_locks_after_repeated_failures` and `::test_successful_login_clears_the_failure_counter` re-run and passing.

## 6. Root cause

No software defect. The activity is the expected consequence of an authentication endpoint being reachable, and the designed control handled it. The underlying exposure — that any internet-facing login form will receive credential-guessing traffic — is tracked as **T-04** in the risk register with an accepted residual score of 6.

## 7. Lessons learned and actions

| # | Finding | Action | Owner | Status |
|---|---|---|---|---|
| 1 | Lockout worked, but the log shows no single event summarising a *campaign* across several accounts | Add a periodic aggregation query over `login_attempts` grouped by source address | Handler | Open |
| 2 | The 15-minute lock is itself an availability lever (risk **T-11**) | Retain the time-bounded design; monitor for repeat targeting of the same account | Handler | Accepted |
| 3 | Timestamps are UTC while the institution operates in WAT | Note the offset in the runbook to avoid confusion during a live review | Handler | Done |
| 4 | Log currently written to the same host as the application | Off-host forwarding recommended before any deployment beyond the lab | System owner | Deferred |

## 8. Evidence index

| Artefact | Location |
|---|---|
| Raw security log | `evidence/logs/security.log` |
| Login/lockout capture | `evidence/captures/E8_lockout_and_ratelimit.txt` |
| Authorisation denials | `evidence/captures/E12_access_control.txt` |
| Password storage evidence | `evidence/captures/E6_password_storage.txt` |
| Regression tests | `evidence/captures/E9_test_results.txt` |

---

*Prepared for the IFT 542 practical assignment. All data is fictitious and all activity was confined to the loopback interface of the author's own machine.*
