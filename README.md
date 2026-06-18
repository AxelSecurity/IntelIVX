# URL Analyzer

Servizio di analisi URL per pipeline di email security. Analizza URL estratti da email tramite browser reale (Playwright/Chromium), estrae segnali di sicurezza e li valuta con un agente AI (Azure AI Foundry) per rilevare phishing, credential harvesting e malware.

---

## Funzionalità

- **Browser-based analysis** — navigazione reale con Chromium headless, nessun evasion possibile
- **Redirect chain tracking** — cattura tutti i redirect (HTTP 3xx, meta-refresh, JS setTimeout)
- **SSL/TLS inspection** — verifica certificati: emittente, scadenza, self-signed, emesso di recente
- **Visual OCR** — estrae testo da immagini e loghi tramite Tesseract per rilevare brand impersonation visiva
- **AI verdict** — agente Azure AI Foundry (GPT-4o) classifica ogni URL con confidence score e motivazione
- **Whitelist / Blacklist** — override manuale per gestire falsi positivi e negativi, persistente su file
- **Trellix IVX integration** — endpoint sincrono nativo per il modulo "Integrate Your Intelligence"
- **Swagger UI** — documentazione API interattiva su `/docs`

---

## Verdetti

| Verdict | Azione | Quando |
|---|---|---|
| `safe` | `allow` | Nessun indicatore di rischio |
| `suspicious` | `quarantine` | Anomalie senza impersonation specifica |
| `malicious` | `block` | Brand impersonation, credential harvesting, HTTP login form |

---

## Requisiti

- Docker + Docker Compose
- Account Azure con Azure AI Foundry Agent configurato
- App Registration Azure AD con ruolo **Foundry User** sul progetto Foundry

---

## Configurazione

```bash
cp .env.example .env
```

Compila `.env`:

```env
# Azure AI Foundry Agent
FOUNDRY_ENDPOINT=https://<resource>.services.ai.azure.com/api/projects/<project>
FOUNDRY_AGENT_NAME=<nome-agente>
FOUNDRY_AGENT_VERSION=<versione>

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

# Trellix IVX — Token Auth (opzionale)
TRELLIX_API_TOKEN=
```

---

## Avvio

```bash
docker compose up --build
```

Il servizio sarà disponibile su `http://localhost:8081`.
Swagger UI: `http://localhost:8081/docs`

---

## API

### Analisi asincrona (email wrapper)

```bash
# Sottometti URL da analizzare
curl -X POST http://localhost:8081/analyze/urls \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://example.com"]}'
# → {"job_id": "abc-123", "status": "pending", "urls_count": 1}

# Polling risultato
curl http://localhost:8081/jobs/abc-123
```

**Risposta job completato:**
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
      "ssl_info": { ... },
      "chain_verdicts": []
    }
  ]
}
```

### Analisi sincrona — Trellix IVX

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
# Aggiungi dominio alla whitelist (falso positivo)
curl -X POST http://localhost:8081/whitelist \
  -H "Content-Type: application/json" \
  -d '{"pattern": "paypal.com", "note": "Dominio legittimo"}'

# Aggiungi dominio alla blacklist (falso negativo)
curl -X POST http://localhost:8081/blacklist \
  -H "Content-Type: application/json" \
  -d '{"pattern": "phishing-domain.xyz", "note": "Phishing confermato"}'

# Lista completa
curl http://localhost:8081/whitelist
curl http://localhost:8081/blacklist

# Rimozione
curl -X DELETE http://localhost:8081/whitelist/paypal.com
```

---

## Integrazione Trellix IVX

Configura il modulo **"Integrate Your Intelligence"** in Trellix IVX:

| Campo | Valore |
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
| Token | valore di `TRELLIX_API_TOKEN` |

---

## Architettura

```
[Email Wrapper / Trellix IVX]
          ↓
    [FastAPI :8081]
          ↓
    [Job Queue]  ←→  [Whitelist/Blacklist]
          ↓
  [Playwright Worker]
    Chromium headless
    Redirect chain tracking
    SSL inspection
    OCR (Tesseract)
          ↓
  [Azure AI Foundry Agent]
    GPT-4o verdict
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

## Struttura progetto

```
url_analyzer/
├── config.py              # Settings da .env
├── main.py                # FastAPI app, endpoints, lifespan
├── models/
│   ├── job.py             # PlaywrightResult, URLVerdict, SSLInfo
│   ├── requests.py        # URLAnalysisRequest, ListEntryRequest
│   └── responses.py       # Response models
├── services/
│   ├── playwright_service.py  # Browser automation + OCR
│   ├── openai_service.py      # Azure AI Foundry agent client
│   ├── job_service.py         # Job creation e retrieval
│   └── list_service.py        # Whitelist/Blacklist CRUD
├── storage/
│   └── job_store.py       # In-memory job store con TTL
└── workers/
    └── analyzer.py        # Worker loop, _analyze_simple, _analyze_with_chain
```

---

## Variabili di configurazione

| Variabile | Default | Descrizione |
|---|---|---|
| `FOUNDRY_ENDPOINT` | — | Azure AI Foundry project endpoint |
| `FOUNDRY_AGENT_NAME` | — | Nome agente nel portale Foundry |
| `FOUNDRY_AGENT_VERSION` | — | Versione agente pubblicata |
| `AZURE_TENANT_ID` | `""` | Azure AD tenant ID |
| `AZURE_CLIENT_ID` | `""` | App Registration client ID |
| `AZURE_CLIENT_SECRET` | `""` | App Registration client secret |
| `PLAYWRIGHT_TIMEOUT_MS` | `30000` | Timeout navigazione Playwright (ms) |
| `PLAYWRIGHT_SCREENSHOT` | `false` | Includi screenshot nel risultato |
| `PLAYWRIGHT_OCR` | `true` | OCR su screenshot per brand visiva |
| `N_WORKERS` | `3` | Worker paralleli per analisi |
| `JOB_TTL_SECONDS` | `3600` | TTL job in memoria (secondi) |
| `TRELLIX_API_TOKEN` | `""` | Bearer token per endpoint Trellix |
