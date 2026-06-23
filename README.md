# URL Analyzer

A URL analysis service for email security pipelines. Analyzes URLs extracted from emails using a real browser (Playwright/Chromium), extracts security signals, and evaluates them with an AI agent (Azure AI Foundry) to detect phishing, credential harvesting, and malware.

---

## Features

- **Browser-based analysis** — real Chromium headless navigation, no evasion possible
- **Redirect chain tracking** — captures all redirects (HTTP 3xx, meta-refresh, JS setTimeout)
- **SSL/TLS inspection** — certificate verification: issuer, expiry, self-signed, recently issued
- **Visual OCR** — extracts text from images and logos via Tesseract to detect visual brand impersonation
- **AI verdict** — Azure AI Foundry agent (GPT-4o) classifies each URL with confidence score and reasoning
- **Whitelist / Blacklist** — manual override to manage false positives and negatives, persisted to file
- **SQLite verdict cache** — persistent cache of analysis results with per-verdict TTL; avoids re-analyzing known URLs
- **Analysis history** — permanent audit log of all analyses (safe included) stored in SQLite
- **IOC Feed** — exposes detected malicious/suspicious URLs as a threat intelligence feed (JSON, TXT, CSV) for firewalls, proxies, and SIEMs
- **Web Dashboard** — authenticated web UI to visualize all analyses, statistics, charts, and manage whitelist/blacklist
- **Trellix IVX integration** — native synchronous endpoint for the "Integrate Your Intelligence" module
- **Swagger UI** — interactive API documentation at `/docs`

---

## Verdicts

| Verdict | Action | When |
|---|---|---|
| `safe` | `allow` | No significant risk indicators |
| `suspicious` | `quarantine` | Anomalies without specific brand impersonation |
| `malicious` | `block` | Brand impersonation, credential harvesting, HTTP login form |

---

## Requirements

- Docker + Docker Compose
- Azure account with a configured Azure AI Foundry Agent
- Azure AD App Registration with the **Foundry User** role on the Foundry project

---

## Configuration

```bash
cp .env.example .env
```

Fill in `.env`:

```env
# Azure AI Foundry Agent
FOUNDRY_ENDPOINT=https://<resource>.services.ai.azure.com/api/projects/<project>
FOUNDRY_AGENT_NAME=<agent-name>
FOUNDRY_AGENT_VERSION=<version>

# Azure AD — Service Principal
AZURE_TENANT_ID=<tenant-id>
AZURE_CLIENT_ID=<client-id>
AZURE_CLIENT_SECRET=<client-secret>

# Playwright
PLAYWRIGHT_TIMEOUT_MS=30000
PLAYWRIGHT_SCREENSHOT=false
PLAYWRIGHT_OCR=true

# Worker
N_WORKERS=3
JOB_TTL_SECONDS=3600

# Trellix IVX — Token Auth (optional)
TRELLIX_API_TOKEN=

# IOC Feed — Token Auth (optional)
IOC_API_TOKEN=

# Dashboard web UI
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=<choose-a-secure-password>
DASHBOARD_SECRET_KEY=<generate-with: python3 -c "import uuid; print(uuid.uuid4())">
```

---

## Getting Started

```bash
docker compose up --build
```

| URL | Description |
|---|---|
| `http://localhost:8081` | API base |
| `http://localhost:8081/docs` | Swagger UI |
| `http://localhost:8081/dashboard` | Web Dashboard |

---

## Web Dashboard

The dashboard provides a visual interface to monitor all analyses and manage the service.

**Access:** `http://localhost:8081/dashboard` — protected by username/password login.

**Features:**
- **Stats cards** — total analyses, threats (malicious + suspicious), safe count
- **Charts** — verdict distribution (pie) and analyses per day last 7 days (bar)
- **Analysis table** — all analyses with filters (verdict, time window, domain search) and pagination
- **Detail modal** — click any row to see full verdict details, risk indicators, and reasoning
- **Per-row actions** — force re-analyze 🔄, add to whitelist ✅, add to blacklist 🚫
- **List management** — add/remove whitelist and blacklist entries directly from the dashboard
- **Auto-refresh** — updates every 30 seconds

> The dashboard shows **all analyses including safe** via a permanent SQLite audit log (`analysis_history` table), separate from the verdict cache.

---

## API

### Async analysis (email wrapper)

```bash
# Submit URLs for analysis
curl -X POST http://localhost:8081/analyze/urls \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://example.com"]}'
# → {"job_id": "abc-123", "status": "pending", "urls_count": 1}

# Poll for results
curl http://localhost:8081/jobs/abc-123
```

**Completed job response:**
```json
{
  "job_id": "abc-123",
  "status": "completed",
  "results": [
    {
      "url": "https://example.com",
      "verdict": "safe",
      "confidence": 0.95,
      "risk_indicators": [],
      "reason": "...",
      "recommended_action": "allow",
      "ssl_info": { "..." },
      "chain_verdicts": []
    }
  ]
}
```

### Synchronous analysis — Trellix IVX

```bash
curl "http://localhost:8081/trellix/analyze?url=https://example.com"
```

```json
{
  "result": {
    "verdict": "malicious",
    "signature": "Brand impersonation PayPal | Login form on mismatched domain",
    "confidence": 0.99,
    "recommended_action": "block",
    "reason": "..."
  }
}
```

### IOC Feed

```bash
# All active IOCs (malicious + suspicious) — JSON for SIEM
curl "http://localhost:8081/ioc"

# Malicious only — TXT for firewall/proxy blocklist (one URL per line)
curl "http://localhost:8081/ioc?verdict=malicious&format=txt"

# Last 24 hours — CSV
curl "http://localhost:8081/ioc?since=24h&format=csv"
```

### Whitelist / Blacklist

```bash
# Add domain to whitelist (false positive override)
curl -X POST http://localhost:8081/whitelist \
  -H "Content-Type: application/json" \
  -d '{"pattern": "paypal.com", "note": "Legitimate domain"}'

# Add domain to blacklist (false negative override)
curl -X POST http://localhost:8081/blacklist \
  -H "Content-Type: application/json" \
  -d '{"pattern": "phishing-domain.xyz", "note": "Confirmed phishing"}'

# List all entries
curl http://localhost:8081/whitelist
curl http://localhost:8081/blacklist

# Remove entry
curl -X DELETE http://localhost:8081/whitelist/paypal.com
```

---

## Trellix IVX Integration

Configure the **"Integrate Your Intelligence"** module in Trellix IVX:

| Field | Value |
|---|---|
| Engine Name | `URL Analyzer` |
| API Endpoint | `<host>:8081/trellix/analyze` |
| Timeout | `60` |
| Verdict Key | `result.verdict` |
| Verdict Value | `malicious` |
| Signature Key | `result.signature` |
| Object Type | `URLs` |
| Placement | `Query Param` |
| Authorization | `Token Auth` / `Bearer` |
| Token | value of `TRELLIX_API_TOKEN` |

---

## Architecture

```
[Email Wrapper / Trellix IVX]
          ↓
    [FastAPI :8081]
          ↓
    [Job Queue]  ←→  [Whitelist/Blacklist]  (priority override)
          ↓
    [SQLite Cache]  ←→  hit: immediate response
          ↓ miss
  [Playwright Worker]
    Chromium headless
    Redirect chain tracking
    SSL inspection
    OCR (Tesseract)
          ↓
  [Azure AI Foundry Agent]
    GPT-4o verdict
          ↓
    [SQLite Cache + Analysis History]  ←→  save result
          ↓
    [Job Result / Dashboard]
```

**Stack:**
- Python 3.10 + FastAPI + asyncio
- Playwright 1.60 (Chromium)
- Tesseract OCR
- Azure AI Foundry (GPT-4o)
- SQLite (aiosqlite) — verdict cache + analysis history
- Jinja2 + Tailwind CSS + Chart.js — web dashboard
- Docker (`mcr.microsoft.com/playwright/python:v1.60.0-jammy`)

---

## Project Structure

```
url_analyzer/
├── config.py                  # Settings loaded from .env
├── main.py                    # FastAPI app, endpoints, dashboard routes
├── models/
│   ├── job.py                 # PlaywrightResult, URLVerdict, SSLInfo
│   ├── requests.py            # URLAnalysisRequest, ListEntryRequest
│   └── responses.py           # Response models
├── services/
│   ├── playwright_service.py  # Browser automation + OCR
│   ├── openai_service.py      # Azure AI Foundry agent client
│   ├── job_service.py         # Job creation and retrieval
│   └── list_service.py        # Whitelist/Blacklist CRUD
├── storage/
│   ├── job_store.py           # In-memory job store with TTL
│   ├── verdict_cache.py       # SQLite persistent verdict cache
│   └── analysis_history.py   # SQLite permanent audit log (all verdicts)
├── templates/
│   ├── base.html              # Dashboard base layout
│   ├── login.html             # Login page
│   └── dashboard.html         # Main dashboard
└── workers/
    └── analyzer.py            # Worker loop, _analyze_simple, _analyze_with_chain
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `FOUNDRY_ENDPOINT` | — | Azure AI Foundry project endpoint |
| `FOUNDRY_AGENT_NAME` | — | Agent name in the Foundry portal |
| `FOUNDRY_AGENT_VERSION` | — | Published agent version |
| `AZURE_TENANT_ID` | `""` | Azure AD tenant ID |
| `AZURE_CLIENT_ID` | `""` | App Registration client ID |
| `AZURE_CLIENT_SECRET` | `""` | App Registration client secret |
| `PLAYWRIGHT_TIMEOUT_MS` | `30000` | Playwright navigation timeout (ms) |
| `PLAYWRIGHT_SCREENSHOT` | `false` | Include screenshot in results |
| `PLAYWRIGHT_OCR` | `true` | OCR on screenshot for visual brand detection |
| `N_WORKERS` | `3` | Parallel analysis workers |
| `JOB_TTL_SECONDS` | `3600` | Job TTL in memory (seconds) |
| `TRELLIX_API_TOKEN` | `""` | Bearer token for Trellix endpoint auth |
| `IOC_API_TOKEN` | `""` | Bearer token for IOC feed endpoint auth |
| `DASHBOARD_USERNAME` | `admin` | Dashboard login username |
| `DASHBOARD_PASSWORD` | `""` | Dashboard login password |
| `DASHBOARD_SECRET_KEY` | `""` | Secret key for session cookie signing |

### Verdict Cache TTL

| Verdict | Cached | TTL | Rationale |
|---|---|---|---|
| `malicious` | ✅ Yes | 30 days | Phishing domains remain active for weeks |
| `suspicious` | ✅ Yes | 3 days | Re-evaluate frequently, may change |
| `safe` | ❌ No | — | Always re-analyzed to catch future compromises |

Safe URLs are never stored in the cache — every request triggers a full Playwright + AI analysis so that a previously clean domain that later becomes malicious is always caught. All analyses (including safe) are recorded in the `analysis_history` audit log for dashboard visibility.

The SQLite database is stored at `./data/verdict_cache.db` on the host and persists across container rebuilds via Docker volume mount.
