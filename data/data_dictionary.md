# Data Dictionary

This document details the schema, provenance, and specifications for the synthetic datasets used in the e-Government Portal Protection project.

## Provenance & Quality Notes
- **Provenance:** All data is synthetic and generated using Faker and Python (NumPy/Pandas) seeded at `42` for reproducibility.
- **PII Controls:** Names and real identifiers are entirely fictionalized. IP addresses use standard documentation ranges.
- **Quality Notes:** Contains planned missing values (~2% null rates on non-key fields) and synthetic anomalies to simulate real-world noise.

## Entity Key Relationships
- `session_id` links WAF logs and API Gateway logs.
- `citizen_id` links API Gateway, Auth/DB Audit logs, and Citizen Complaints.
- `src_ip` connects WAF logs, API Gateway logs, and Auth/DB Audit logs.

### IP Address Routing Policy (Simulated)
- `192.0.2.0/24`: Legitimate/Normal User Traffic
- `198.51.100.0/24`: Scanning/Reconnaissance Traffic
- `203.0.113.0/24`: Malicious/Botnet Infrastructure

---

## 1. web_waf_logs.csv
**Description:** Web and WAF HTTP request logs capturing all initial edge interactions.
**Approximate Record Count:** ~6,000

| Column Name | Data Type | Description | Example Value | Nullable | Constraints |
|-------------|-----------|-------------|---------------|----------|-------------|
| `event_id` | str | Unique event identifier | EVT-1A2B3C4D | No | Format: EVT-XXXXXXXX |
| `timestamp` | datetime | ISO 8601 UTC timestamp | 2026-09-08T14:22:10Z | No | - |
| `src_ip` | str | Source IP address | 192.0.2.45 | No | Reserved ranges only |
| `session_id` | str | UUID4 session tracker | 123e4567-e89b-12d3... | Yes | UUID format |
| `http_method` | str | HTTP request verb | GET, POST | No | GET/POST/PUT/DELETE/OPTIONS |
| `url_path` | str | Requested URI path | /login | No | - |
| `status_code` | int | HTTP response code | 200, 403, 500 | No | 200-503 |
| `user_agent` | str | Client User-Agent string | Mozilla/5.0... | Yes | - |
| `bytes_sent` | int | Size of response in bytes | 1024 | No | >= 0 |
| `waf_action` | str | WAF disposition | ALLOW | No | ALLOW/BLOCK/CHALLENGE |
| `attack_type` | str | Threat classification | BENIGN | No | BENIGN/CREDENTIAL_STUFFING/SQLI... |
| `country` | str | GeoIP country location | NA | Yes | 2-letter ISO |

---

## 2. api_gateway_logs.csv
**Description:** API Gateway microservice call logs representing backend data access.
**Approximate Record Count:** ~4,000

| Column Name | Data Type | Description | Example Value | Nullable | Constraints |
|-------------|-----------|-------------|---------------|----------|-------------|
| `event_id` | str | Unique event identifier | EVT-8X7Y6Z5W | No | Format: EVT-XXXXXXXX |
| `timestamp` | datetime | ISO 8601 UTC timestamp | 2026-09-08T14:22:11Z | No | - |
| `session_id` | str | UUID4 session tracker | 123e4567-e89b-12d3... | Yes | Links to WAF |
| `src_ip` | str | Source IP address | 192.0.2.45 | No | - |
| `endpoint` | str | API endpoint called | /api/v1/tax/status | No | - |
| `token_id` | str | Auth token identifier | TOK-A1B2C3D4 | No | Format: TOK-XXXXXXXX |
| `citizen_id` | str | Citizen identifier | CIT-123456 | No | Format: CIT-XXXXXX |
| `request_payload_bytes`| int | Payload size | 512 | No | >= 0 |
| `response_time_ms` | float | Processing latency | 45.2 | No | > 0.0 |
| `http_status` | int | Internal API HTTP code | 200 | No | 200-503 |
| `is_anomalous_scraping`| int | Flag for scraping | 0 or 1 | No | 0/1 Boolean |

---

## 3. auth_db_audit_logs.csv
**Description:** Database auditing and authentication logs for sensitive record access.
**Approximate Record Count:** ~3,500

| Column Name | Data Type | Description | Example Value | Nullable | Constraints |
|-------------|-----------|-------------|---------------|----------|-------------|
| `event_id` | str | Unique event identifier | EVT-4D3C2B1A | No | Format: EVT-XXXXXXXX |
| `timestamp` | datetime | ISO 8601 UTC timestamp | 2026-09-08T14:22:15Z | No | - |
| `citizen_id` | str | Affected citizen ID | CIT-123456 | No | Format: CIT-XXXXXX |
| `auth_event` | str | Type of auth/db action | LOGIN_SUCCESS | No | - |
| `src_ip` | str | Originating IP | 192.0.2.45 | No | - |
| `geo_country` | str | Geo-located country | NA | Yes | - |
| `geo_city` | str | Geo-located city | Windhoek | Yes | - |
| `latitude` | float | Geo-latitude | -22.5594 | Yes | -90.0 to 90.0 |
| `longitude` | float | Geo-longitude | 17.0832 | Yes | -180.0 to 180.0 |
| `db_query` | str | SQL query executed | SELECT * FROM users | Yes | - |
| `rows_returned` | int | Number of rows accessed | 1 | No | >= 0 |
| `db_execution_ms` | float | Database query latency | 12.5 | No | >= 0.0 |
| `is_impossible_travel` | int | Impossible travel flag | 0 or 1 | No | 0/1 Boolean |

---

## 4. citizen_complaints.json
**Description:** Unstructured citizen support tickets reporting fraud or account anomalies.
**Approximate Record Count:** ~300

| Column Name | Data Type | Description | Example Value | Nullable | Constraints |
|-------------|-----------|-------------|---------------|----------|-------------|
| `ticket_id` | str | Support ticket ID | TKT-987654 | No | Format: TKT-XXXXXX |
| `timestamp` | datetime | ISO 8601 UTC timestamp | 2026-09-09T08:00:00Z | No | - |
| `citizen_id` | str | Submitting citizen ID | CIT-123456 | No | Format: CIT-XXXXXX |
| `reported_ip` | str | IP reported by user | 203.0.113.10 | Yes | - |
| `complaint_text`| str | Unstructured text | "My account was hacked" | No | - |
| `urgency_level` | str | Priority level | HIGH | No | LOW/MEDIUM/HIGH/CRITICAL |
| `category` | str | Ticket categorization | ACCOUNT_COMPROMISE | No | - |
