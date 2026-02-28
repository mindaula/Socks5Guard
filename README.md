# Socks5Guard

SOCKS5 proxy validation and abuse-intelligence service with optional offline geolocation enrichment.

## 1. Project Overview

### Purpose
Socks5Guard validates SOCKS5 proxies, classifies failed and high-risk entries, and exposes results through an authenticated HTTP API. The companion `Socks5GeoChecker.py` script enriches proxy lists with city/country metadata via IPInfo.

### Problem It Solves
Security teams often need a repeatable way to:
- Test whether proxy endpoints are operational.
- Separate unusable proxies from candidates worth further review.
- Flag potentially abusive infrastructure using threat-intelligence context.
- Export machine-readable outputs for automation.

### High-Level Architecture (ASCII)

```text
+--------------------+        +---------------------------+
| Worker Loop        |        | Flask API Thread          |
| (main thread)      |        | /blacklist /not_working   |
|                    |        | /shutdown                 |
+---------+----------+        +-------------+-------------+
          |                                 |
          v                                 v
+----------------------+        +--------------------------+
| ThreadPoolExecutor   |<------>| Shared In-Memory Sets    |
| check_proxy() tasks  |  lock  | blacklist/not_working    |
+----------+-----------+        +-------------+------------+
           |                                   |
           v                                   v
+----------------------+          +--------------------------+
| AbuseIPDB + Proxy    |          | atomic JSON persistence |
| network checks       |          | blacklist.json          |
+----------------------+          | not_working.json        |
                                  +--------------------------+
```

### Intended Use Cases
- Internal security tooling.
- Automated triage pipelines for proxy hygiene.
- Input preparation for downstream SOC/SIEM workflows.

### Explicit Non-Goals
- It is not a full proxy scraper in current implementation.
- It is not a hardened public internet service.
- It is not horizontally scalable out of the box.
- It is not a real-time distributed scanning framework.

## 2. Architecture

### Worker Loop
`Socks5Guard.py` starts a periodic loop that validates a configured static proxy list and persists snapshots every cycle.

### Validation Pipeline
For each `ip:port` entry:
1. Format check.
2. SOCKS5 TCP connect test (`1.1.1.1:80`).
3. HTTP forwarding test (`https://httpbin.org/ip`).
4. AbuseIPDB classification (when API key is present and lookup succeeds).

### AbuseIPDB Integration
- Uses `/api/v2/check` with `maxAgeInDays=90`.
- `abuseConfidenceScore > 50` is considered malicious.
- Missing key or request failures are treated as **unknown**, not malicious.

### Threading Model
- Proxy validation runs in `ThreadPoolExecutor` with bounded worker count.
- Large lists are processed in chunks (`MAX_PROXY_LIMIT`) rather than skipped.
- Shared sets are lock-protected.
- Outbound external calls are semaphore-limited (`MAX_EXTERNAL_CONCURRENCY`).

### API Server Model
- Flask app runs in a daemon thread when the script is started directly.
- Endpoints are authenticated using `X-API-KEY`.
- Service fails closed if `API_KEY` is missing.

### Data Persistence Flow
- `blacklist` and `not_working` are snapshotted with deterministic sorting.
- Files are written atomically (`tempfile + os.replace`) to avoid partial reads.

### Runtime Flow (ASCII)

```text
Start
  |
  v
Load env/config -> start Flask thread -> verify API thread alive
  |
  v
while not stop_event:
  build proxy list (static in current code)
  -> worker(): chunk list, run thread pool, classify entries
  -> save_lists(): atomic write blacklist.json + not_working.json
  -> wait interval
```

## 3. Security Model

### Fail-Closed Philosophy
- If `API_KEY` is unset, protected API endpoints return `503`.
- This prevents accidental anonymous exposure due to deployment mistakes.

### API Key Enforcement
- Required on `/blacklist`, `/not_working`, and `/shutdown`.
- Compared using constant-time `compare_digest`.

### Endpoint Protection
- `/shutdown` requires:
  - valid API key
  - localhost source (`127.0.0.1` or `::1`)
- On accepted shutdown, `stop_event` is set so worker and API lifecycle remain consistent.

### AbuseIPDB Handling
- Lookup failures do not automatically blacklist entries.
- Unknown reputation is logged and treated separately from confirmed maliciousness.

### Known Attack Surfaces
- Resource pressure from large proxy sets.
- Outbound dependency instability (AbuseIPDB/IPInfo availability).
- Misconfigured API keys.
- Running Flask development server in exposed networks.

### Misconfiguration Warnings
- Do not expose this directly on public internet.
- Do not run without `API_KEY` in environments where API access matters.
- Protect `.env` and key material.

## 4. Installation

### Python Version
- Recommended: Python 3.10+

### Dependencies
From `requirements.txt`:
- `requests`
- `flask`
- `PySocks`
- `beautifulsoup4`
- `python-dotenv`

### Virtual Environment Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### `.env` Configuration Example

```env
API_KEY=replace_with_strong_random_value
ABUSEIPDB_API_KEY=replace_with_abuseipdb_key
IPINFO_API_KEY=replace_with_ipinfo_token

MAX_PROXY_LIMIT=5000
MAX_PROXY_THREADS=50
MAX_EXTERNAL_CONCURRENCY=4
```

## 5. Usage

### Run Main Validator

```bash
python Socks5Guard.py
```

### Run Geo Checker

```bash
python Socks5GeoChecker.py blacklist.json
```

## 6. API Endpoints

All endpoints require header:

```text
X-API-KEY: <API_KEY>
```

If `API_KEY` is not configured, protected endpoints return `503`.

### `GET /blacklist`
Returns sorted JSON list of proxies classified as malicious.

Example:

```bash
curl -H "X-API-KEY: ${API_KEY}" http://127.0.0.1:5000/blacklist
```

### `GET /not_working`
Returns sorted JSON list of proxies that failed validation.

Example:

```bash
curl -H "X-API-KEY: ${API_KEY}" http://127.0.0.1:5000/not_working
```

### `POST /shutdown`
Requests controlled shutdown (localhost + API key required).

Example:

```bash
curl -X POST -H "X-API-KEY: ${API_KEY}" http://127.0.0.1:5000/shutdown
```

## 7. Output Files

### `blacklist.json`
- Type: JSON array of strings.
- Entries: `"ip:port"` proxies with high abuse confidence.

### `not_working.json`
- Type: JSON array of strings.
- Entries: `"ip:port"` proxies that failed connectivity/forwarding/format checks.

### Output Guarantees
- Deterministic ordering (sorted snapshots).
- Atomic file replacement to minimize partial-read corruption windows.

## 8. Limitations

- No live scraping in current implementation (static proxy list only unless you extend code).
- Blocking I/O networking model.
- Best suited for small to medium internal workloads.
- No horizontal scaling/coordinator logic.
- Not hardened for hostile public internet exposure.

## 9. Production Considerations

- Put service behind a reverse proxy (TLS termination, IP filtering, request limits).
- Add rate limiting and authentication hardening (rotated secrets, vault-backed env).
- Monitor thread usage and outbound timeout/error rates.
- Plan for dependency outages (AbuseIPDB/IPInfo) and alert on prolonged degradation.
- Forward logs to centralized logging with retention and alerting policies.

## 10. Testing & Verification

### Dependency Verification

```bash
python -m py_compile Socks5Guard.py Socks5GeoChecker.py
```

### Manual Endpoint Checks

```bash
curl -i -H "X-API-KEY: ${API_KEY}" http://127.0.0.1:5000/blacklist
curl -i -H "X-API-KEY: ${API_KEY}" http://127.0.0.1:5000/not_working
curl -i -X POST -H "X-API-KEY: ${API_KEY}" http://127.0.0.1:5000/shutdown
```

### Simulate Proxy Failures
Use intentionally invalid entries in the static proxy list inside `Socks5Guard.py` (for example invalid ports or unreachable hosts) and verify they appear in `not_working.json`.

### Geo Checker Validation

```bash
python Socks5GeoChecker.py blacklist.json
cat blacklist_with_city.json
```

## 11. License

This project is provided under the MIT License. Include a `LICENSE` file containing the MIT license text in the repository root.
