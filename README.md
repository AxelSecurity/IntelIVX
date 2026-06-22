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
```

---

## Getting Started

```bash
docker compose up --build
```

The service will be available at `http://localhost:8081`.  
Swagger UI: `http://localhost:8081/docs`

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
    [SQLite Cache]  ←→  save result
          ↓
    [Job Result]
```

**Stack:**
- Python 3.10 + FastAPI + asyncio
- Playwright 1.60 (Chromium)
- Tesseract OCR
- Azure AI Foundry (GPT-4o)
- Docker (`mcr.microsoft.com/playwright/python:v1.60.0-jammy`)

---

## Project Structure

```
url_analyzer/
├── config.py                  # Settings loaded from .env
├── main.py                    # FastAPI app, endpoints, lifespan
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
│   └── verdict_cache.py       # SQLite persistent verdict cache
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

### Verdict Cache TTL

| Verdict | TTL | Rationale |
|---|---|---|
| `malicious` | 30 days | Phishing domains remain active for weeks |
| `suspicious` | 3 days | Re-evaluate frequently, may change |
| `safe` | 7 days | Legitimate domains are stable but not permanent |

The SQLite database is stored at `./data/verdict_cache.db` on the host and persists across container rebuilds via Docker volume mount.
