# Incident Response Playbook: Credential Stuffing
**Framework Alignment:** NIST SP 800-61r2
**Target Environment:** e-Government Portal 

## 1. Preparation
- **Pre-incident checklist:** Ensure logging covers WAF, API gateway, and Auth DB. Baseline normal login failure rates.
- **Required tools and access:** Access to WAF console, SIEM/Log Management (containing `web_waf_logs` and `api_gateway_logs`), AD/IdP administrative access.
- **Communication plan:** Pre-defined comms templates for compromised citizens. Notification matrix including CISO, DPO (Data Protection Officer), and Legal.
- **Escalation matrix:** L1 SOC -> L2 Incident Responder -> Identity & Access Management (IAM) Team -> CISO.

## 2. Detection & Analysis
- **Indicators of Compromise (IOCs):**
  - High volume of `POST /login` or `POST /api/v1/auth` from single or distributed IPs (e.g., `203.0.113.0/24`).
  - Spikes in HTTP 401/403 status codes.
  - `auth_event` logs showing multiple `LOGIN_FAILURE` followed by `LOGIN_SUCCESS` for the same `citizen_id` from unusual IPs.
  - Complaints in `citizen_complaints.json` regarding unrecognized logins or password resets.
- **Alert triage criteria:** > 50 failed logins per minute from a single ASN or > 500 failed logins globally over 5 minutes.
- **Evidence collection procedures:** Export logs matching the incident timeframe. Retain memory dumps of WAF instances if anomalous payloads are found.
- **Severity classification:** HIGH (Potential PII exposure, breach of e-Gov portal integrity).

## 3. Containment
- **Short-term:**
  - Enforce strict rate limiting on `/login` and authentication APIs (e.g., max 5 attempts / 5 mins).
  - Dynamically block attacking IPs (e.g., drop traffic from `203.0.113.0/24`).
  - Enforce multi-factor authentication (MFA) step-up for all suspicious successful logins.
- **Long-term:**
  - Update WAF managed rule groups to block known malicious botnet ASNs.
  - Force password resets for accounts confirmed compromised.
  - Revoke associated API tokens (`token_id`) and active `session_id`s.
- **Evidence preservation:** Secure backup of `auth_db_audit_logs.csv` and WAF telemetry in an immutable storage container.

## 4. Eradication
- **Compromised account identification:** Query database for all `LOGIN_SUCCESS` events originating from known bad IPs within the incident window.
- **Botnet IP blocklist updates:** Push finalized bad IPs to edge routers, WAFs, and threat intelligence sharing platforms (using STIX2).
- **WAF signature deployment:** Deploy custom WAF signatures detecting the specific User-Agent or header anomalies used by the credential stuffing tools.
- **Database access audit:** Review `auth_db_audit_logs` and `api_gateway_logs` to ensure compromised `citizen_id`s did not execute anomalous `db_query` or scrape excessive payloads (`request_payload_bytes`).

## 5. Recovery
- **Account restoration procedures:** Assist affected citizens in recovering their accounts via secure out-of-band channels (e.g., SMS/in-person verification).
- **Citizen notification requirements:** Draft and send notifications compliant with POPIA/local data protection laws detailing the extent of access and mitigation steps.
- **Service restoration validation:** Test login pathways to ensure rate limits and MFA blocks are functioning correctly without severely impacting legitimate traffic (`192.0.2.0/24`).
- **Enhanced monitoring period:** Heightened SOC monitoring on the authentication endpoints for 7 days post-incident.

## 6. Post-Incident Activity
- **Lessons learned documentation:** Conduct a debriefing session with L1, L2, and IAM teams within 48 hours of closure.
- **Control effectiveness assessment:** Evaluate why the initial credential stuffing attempts bypassed existing WAF controls.
- **Policy/procedure updates:** Update password complexity requirements or mandate MFA for all e-Gov access.
- **Metrics and reporting:** Generate a report detailing Time to Detect (TTD), Time to Respond (TTR), total compromised accounts, and financial/data risk quantified.
