# Declaration of Ethical and Lawful Professional Conduct

**Course:** IFT 542 — Web Application Security
**Assessment:** Practical Assignment — Security Assessment and Hardening of a Student Registration Web Application
**Department:** Information Technology, School of Information and Communication Technology
**Institution:** Federal University of Technology, Minna

**Name:** Abayomi Favour T.
**Matriculation number:** 2021/01/84091CF
**Date:** 3 August 2026

---

## 1. Scope of testing

I declare that every security test described in this submission was carried out **exclusively against an isolated instance of the application running on the loopback interface (127.0.0.1) of a machine I own and control.**

Specifically, I confirm that I did **not**:

- scan, probe, enumerate or test any system belonging to the Federal University of Technology, Minna;
- direct any request at a public website, a third-party service, a cloud metadata endpoint or any host outside my own machine;
- use any credential belonging to a real person;
- process, store or transmit any real student's personal data.

The destinations named in the SSRF evidence (`127.0.0.1`, `localhost`, `10.0.0.5`, `169.254.169.254`, `docs.futminna.test`) appear only as **inputs that the application refused**. Each was rejected by the destination policy before any socket was opened, which is the point the evidence is intended to demonstrate. The `.test` domain is reserved by RFC 6761 for exactly this purpose and resolves to nothing.

## 2. Data used

All accounts, names, matriculation numbers, e-mail addresses, telephone numbers and uploaded files in this submission are fictitious and were generated for the assignment. The lab accounts use the reserved `.test` domain. No credential in the repository grants access to any real system.

## 3. Handling of the vulnerable code

The submission contains one file, `insecure_baseline/legacy_login.py`, that preserves the original prototype's defective authentication code. It is retained solely so the report can show a genuine before-and-after comparison and so the regression tests can prove the defect is absent from the hardened build. It is not imported by the running application, is never bound to a network port, and is loaded only by the test suite against a throwaway in-memory database.

In line with the assignment's safe-demonstration requirement, I have **not** included reusable attack tooling, automated exploitation scripts, or payload collections. The test suite uses a single well-documented textbook input string as a comparison case to show that the same value which alters the legacy statement is treated as inert data by the parameterised one.

## 4. Secrets and disclosure

No live secret, API key, session token or production credential appears anywhere in this repository. The application refuses to start in its production profile unless a signing key is supplied from the environment, and `.env` is excluded from version control. The lab passwords printed by the seed script are generated at seed time and are meaningful only within a throwaway local database. Password hashes shown in the evidence are truncated so that no salt or digest is published.

## 5. Professional conduct

I understand that the techniques studied in this course can cause real harm if applied to systems without authorisation, and that doing so would breach the Cybercrimes (Prohibition, Prevention, etc.) Act 2015 of the Federal Republic of Nigeria, the Nigeria Data Protection Act 2023, and the regulations of this University. I undertake to apply these techniques only with the documented, informed permission of a system's owner, to keep any vulnerability I discover confidential until it is remediated, and to report findings responsibly to the party able to fix them.

## 6. Academic integrity

This submission is my own work. Where I have relied on published guidance — principally the OWASP Top Ten (2021), the OWASP Cheat Sheet Series, the Microsoft STRIDE methodology and NIST SP 800-61 Rev. 2 — I have cited it in the references section of the report. Any assistance received is acknowledged there.

---

**Signed:** *Abayomi Favour T.*

**Matriculation number:** 2021/01/84091CF

**Date:** 3 August 2026
