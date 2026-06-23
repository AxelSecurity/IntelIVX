# CLAUDE.md — URL Analyzer project context

This file is read automatically by Claude Code at the start of every session.
It captures architectural decisions, known issues, and development history
so future modifications can be made with full context.

---

## What this project is

A FastAPI microservice that analyzes URLs extracted from emails for phishing/malware.
It is part of an email security pipeline. The email wrapper extracts URLs and submits
them here for analysis. Results feed into Trellix IVX sandbox via a dedicated endpoint.

**Deployment**: Docker on a Linux host (WSL2 on Windows during development).
**Port**: 8081.

---

## Key architectural decisions

### Async job queue (POST /analyze/urls)
The main analysis endpoint is async: returns a `job_id` immediately, the caller polls
`GET /jobs/{job_id}`. This allows batch submission (up to 50 URLs) without blocking.
The email wrapper uses this pattern.

### Synchronous endpoint for Trellix IVX (GET /trellix/analyze)
Trellix IVX "Integrate Your Intelligence" requires a single synchronous HTTP call
with the result in the response body. We use `_analyze_simple()` (not `_analyze_with_chain()`)
to stay within the 55-second timeout. The URL is passed as a query parameter.

### Two analysis functions in workers/analyzer.py
- `_analyze_simple(url)`: 1 Playwright session + 1 AI call. Used by Trellix endpoint.
- `_analyze_with_chain(url)`: analyzes each redirect hop separately in parallel
  (`asyncio.gather`), then synthesizes with a second AI call. Used by async job worker.

### Azure AI Foundry Agent (not direct OpenAI)
We use the Azure AI Foundry Agent Service via `openai_client.responses.create()` with
`extra_body={"agent_reference": {"name": ..., "version": ..., "type": "agent_reference"}}`.
The agent has its own system prompt configured in the Foundry portal — we do NOT send
a system prompt in code. Authentication uses `ClientSecretCredential` (service principal)
or `DefaultAzureCredential` as fallback.

**Critical**: the SDK is `azure-ai-projects>=2.1.0`. In version 2.x, `client.agents`
is the ML model registry, NOT the conversational agent service. The correct pattern is:
```python
project_client = AIProjectClient(endpoint=..., credential=...)
openai_client = project_client.get_openai_client()
openai_client.responses.create(...)
```
Calls are wrapped in `asyncio.to_thread()` because `get_openai_client()` returns a
synchronous client.

### SQLite verdict cache (storage/verdict_cache.py)
Before running Playwright+AI, we check SQLite for a cached verdict.
**Safe URLs are never cached** — they are always re-analyzed to catch future compromises.
Only `malicious` (30 days TTL) and `suspicious` (3 days TTL) are cached.
Whitelist/blacklist take absolute priority over the cache.

### Whitelist/Blacklist (services/list_service.py)
Domain-level matching with subdomain support. `paypal.com` matches `www.paypal.com`.
Blacklist takes precedence over whitelist. Persisted to `lists.json`.
Check order: whitelist/blacklist → cache → full analysis.

### OCR for visual brand impersonation (playwright_service.py)
After page load, we take a viewport screenshot and run Tesseract OCR on it.
This detects brand names embedded in images/logos (e.g. university phishing where
the institution name appears only as an image, not in HTML text).
The extracted text goes into `PlaywrightResult.ocr_detected_text` and is included
in the AI analysis payload.

---

## Trellix IVX integration details

**Health check URL**: Trellix sends `secure.eicar.org/eicar_com.zip` (EICAR test file)
as its health check. This domain is auto-added to the blacklist at startup so the health
check always returns `malicious` immediately.

**Double-encoded URLs**: Trellix sends URLs double-encoded (`%253A` instead of `%3A`).
We apply `urllib.parse.unquote()` a second time in the Trellix endpoint to normalize.

**JSON response structure**:
```json
{"result": {"verdict": "malicious", "signature": "...", "confidence": 0.99,
            "recommended_action": "block", "reason": "..."}}
```
Trellix configuration: Verdict Key = `result.verdict`, Signature Key = `result.signature`.

**Bearer token auth**: `TRELLIX_API_TOKEN` in `.env`. If empty, no auth is required.

---

## Playwright redirect detection

Two-phase wait after `goto()` with `wait_until="domcontentloaded"`:
1. `wait_for_load_state("networkidle", timeout=3000)` — catches immediate redirects
2. If URL unchanged after networkidle: `wait_for_url(lambda u: u != original, timeout=4000)`
   — catches deferred JS redirects (setTimeout-based). After detection, waits for
   `networkidle` again with 4s timeout to let the full chain settle.

This was added to fix cases where phishing pages use `setTimeout(fn, 1000)` to redirect
only after a 1-second delay (which fires after networkidle on the initial page).

---

## Known issues and fixes applied

- **azure-ai-projects 2.x**: `create_thread()` does not exist. Use `responses.create()`.
- **Trellix double-encoded URLs**: fixed with `unquote(url)` at endpoint entry.
- **EICAR health check**: fixed by auto-adding `eicar.org` to blacklist at startup.
- **Docker build cache corruption**: if `parent snapshot does not exist: not found`,
  run `docker builder prune --force && docker compose up --build`.
- **OCR requires rebuild**: Tesseract is installed at build time in Dockerfile.
  Any change to Tesseract/Pillow/pytesseract requires `docker compose up --build`.

---

## File layout

```
url_analyzer/
├── config.py                  # All settings from .env via pydantic-settings
├── main.py                    # FastAPI app: all endpoints + lifespan
├── models/
│   ├── job.py                 # PlaywrightResult, URLVerdict, SSLInfo, Job
│   ├── requests.py            # URLAnalysisRequest, ListEntryRequest
│   └── responses.py           # TrellixAnalysisResponse, TrellixResult, etc.
├── services/
│   ├── playwright_service.py  # Chromium automation + SSL + OCR
│   ├── openai_service.py      # Azure AI Foundry agent calls (sync + asyncio.to_thread)
│   ├── job_service.py         # Job creation / retrieval / queue
│   └── list_service.py        # Whitelist/Blacklist CRUD (lists.json)
├── storage/
│   ├── job_store.py           # In-memory job store with TTL + async lock
│   └── verdict_cache.py       # SQLite persistent verdict cache (aiosqlite)
└── workers/
    └── analyzer.py            # _analyze_simple, _analyze_with_chain, worker loop
```

Runtime data (excluded from git):
- `lists.json` — whitelist/blacklist entries
- `data/verdict_cache.db` — SQLite verdict cache (Docker volume: `./data:/app/data`)

---

## Environment variables (key ones)

| Variable | Notes |
|---|---|
| `FOUNDRY_ENDPOINT` | Full project URL including `/api/projects/<name>` |
| `FOUNDRY_AGENT_NAME` | Agent name as shown in Foundry portal |
| `FOUNDRY_AGENT_VERSION` | Published version number (string, e.g. `"4"`) |
| `AZURE_TENANT_ID/CLIENT_ID/CLIENT_SECRET` | Service principal for Foundry auth |
| `PLAYWRIGHT_OCR` | Set `false` to disable OCR (faster, less accurate) |
| `TRELLIX_API_TOKEN` | Empty = no auth on Trellix endpoint |

---

## Development workflow

- No rebuild needed for Python-only changes (uvicorn reloads automatically in Docker)
- Rebuild required when: `requirements.txt` changes, `Dockerfile` changes
- Rebuild command: `docker compose down && docker compose up --build`
- Swagger UI: `http://localhost:8081/docs`
- GitHub repo: `https://github.com/AxelSecurity/IntelIVX`
