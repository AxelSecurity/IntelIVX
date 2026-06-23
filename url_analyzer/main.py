import asyncio
import csv
import io
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import unquote

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, Security, status
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from url_analyzer.config import settings
from url_analyzer.models.requests import ListEntryRequest, URLAnalysisRequest
from url_analyzer.models.responses import (
    HealthResponse,
    IOCEntry,
    IOCFeedResponse,
    JobCreatedResponse,
    JobStatusResponse,
    ListEntryResponse,
    ListResponse,
    TrellixAnalysisResponse,
    TrellixResult,
)
from url_analyzer.services.job_service import cancel_job, create_job, get_job, get_queue
from url_analyzer.services.list_service import list_service
from url_analyzer.services.playwright_service import playwright_service
from url_analyzer.storage.analysis_history import analysis_history
from url_analyzer.storage.verdict_cache import verdict_cache
from url_analyzer.workers.analyzer import _analyze_simple, _analyze_with_chain, cleanup_loop, start_workers

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

# ── Trellix Token Auth ────────────────────────────────────────────────────────
_bearer_scheme = HTTPBearer(auto_error=False)


async def _require_trellix_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(_bearer_scheme),
) -> None:
    """Valida il token Bearer se TRELLIX_API_TOKEN è configurato nel .env."""
    token = settings.trellix_api_token
    if not token:
        return  # autenticazione disabilitata
    if credentials is None or credentials.credentials != token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def _require_ioc_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(_bearer_scheme),
) -> None:
    """Valida il token Bearer per /ioc se IOC_API_TOKEN è configurato nel .env."""
    token = settings.ioc_api_token
    if not token:
        return
    if credentials is None or credentials.credentials != token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )


_worker_tasks = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    await playwright_service.start()
    logger.info("Playwright browser started")

    await list_service.load()
    logger.info("Whitelist/Blacklist loaded")

    await verdict_cache.init()
    logger.info("Verdict cache initialized")

    await analysis_history.init()
    logger.info("Analysis history initialized")

    # eicar.org è il dominio EICAR standard usato da Trellix IVX come health check URL.
    # Deve sempre rispondere malicious — lo aggiungiamo alla blacklist se non presente.
    if not list_service.check_url("https://secure.eicar.org/"):
        await list_service.add(
            "blacklist",
            "eicar.org",
            "EICAR test malware domain — Trellix IVX health check URL",
        )
        logger.info("Auto-added eicar.org to blacklist (Trellix health check)")

    tasks = await start_workers(settings.n_workers)
    _worker_tasks.extend(tasks)

    import asyncio
    asyncio.create_task(cleanup_loop())

    logger.info("%d workers started", settings.n_workers)
    yield

    for t in _worker_tasks:
        t.cancel()
    await playwright_service.stop()
    logger.info("Shutdown complete")


app = FastAPI(
    title="URL Analyzer",
    description="Analyzes URLs via Playwright + Azure OpenAI for phishing/malicious content detection.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(SessionMiddleware, secret_key=settings.dashboard_secret_key or "dev-secret-change-me")

templates = Jinja2Templates(directory="url_analyzer/templates")


# ── Dashboard helpers ─────────────────────────────────────────────────────────

def _dashboard_user(request: Request) -> Optional[str]:
    return request.session.get("dashboard_user")

def _require_dashboard_auth(request: Request) -> str:
    user = _dashboard_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_302_FOUND,
            headers={"Location": "/dashboard/login"},
        )
    return user


# ── Analysis ──────────────────────────────────────────────────────────────────

@app.post("/analyze/urls", response_model=JobCreatedResponse, status_code=status.HTTP_202_ACCEPTED,
          tags=["Analysis"])
async def submit_urls(request: URLAnalysisRequest) -> JobCreatedResponse:
    job = await create_job(request)
    return JobCreatedResponse(
        job_id=job.job_id,
        status=job.status,
        urls_count=len(job.urls),
    )


@app.get("/jobs/{job_id}", response_model=JobStatusResponse, tags=["Analysis"])
async def get_job_status(job_id: str) -> JobStatusResponse:
    job = await get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobStatusResponse(
        job_id=job.job_id,
        status=job.status,
        created_at=job.created_at,
        completed_at=job.completed_at,
        urls_count=len(job.urls),
        results=job.results,
        errors=job.errors,
    )


@app.delete("/jobs/{job_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Analysis"])
async def delete_job(job_id: str) -> None:
    cancelled = await cancel_job(job_id)
    if not cancelled:
        job = await get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found")
        raise HTTPException(
            status_code=409,
            detail=f"Job is {job.status} and cannot be cancelled",
        )


# ── Whitelist ─────────────────────────────────────────────────────────────────

@app.get("/whitelist", response_model=ListResponse, tags=["Lists"])
async def get_whitelist() -> ListResponse:
    entries = list_service.get_all("whitelist")
    return ListResponse(
        list_type="whitelist",
        entries=[ListEntryResponse(domain=e.domain, note=e.note, added_at=e.added_at) for e in entries],
        count=len(entries),
    )


@app.post("/whitelist", response_model=ListEntryResponse, status_code=201, tags=["Lists"])
async def add_to_whitelist(req: ListEntryRequest) -> ListEntryResponse:
    e = await list_service.add("whitelist", req.pattern, req.note)
    return ListEntryResponse(domain=e.domain, note=e.note, added_at=e.added_at)


@app.delete("/whitelist/{domain}", status_code=204, tags=["Lists"])
async def remove_from_whitelist(domain: str) -> None:
    if not await list_service.remove("whitelist", domain):
        raise HTTPException(status_code=404, detail="Entry not found in whitelist")


# ── Blacklist ─────────────────────────────────────────────────────────────────

@app.get("/blacklist", response_model=ListResponse, tags=["Lists"])
async def get_blacklist() -> ListResponse:
    entries = list_service.get_all("blacklist")
    return ListResponse(
        list_type="blacklist",
        entries=[ListEntryResponse(domain=e.domain, note=e.note, added_at=e.added_at) for e in entries],
        count=len(entries),
    )


@app.post("/blacklist", response_model=ListEntryResponse, status_code=201, tags=["Lists"])
async def add_to_blacklist(req: ListEntryRequest) -> ListEntryResponse:
    e = await list_service.add("blacklist", req.pattern, req.note)
    return ListEntryResponse(domain=e.domain, note=e.note, added_at=e.added_at)


@app.delete("/blacklist/{domain}", status_code=204, tags=["Lists"])
async def remove_from_blacklist(domain: str) -> None:
    if not await list_service.remove("blacklist", domain):
        raise HTTPException(status_code=404, detail="Entry not found in blacklist")


# ── Trellix IVX ───────────────────────────────────────────────────────────────

@app.get(
    "/trellix/analyze",
    response_model=TrellixAnalysisResponse,
    tags=["Trellix IVX"],
    summary="Synchronous URL analysis for Trellix IVX 'Integrate Your Intelligence'",
)
async def trellix_analyze(
    url: str = Query(..., description="URL to analyze"),
    _: None = Depends(_require_trellix_token),
) -> TrellixAnalysisResponse:
    """
    Endpoint sincrono compatibile con Trellix IVX.
    Restituisce il verdetto in una singola risposta (no polling).

    **Configurazione Trellix IVX:**
    - Verdict Key: `result.verdict`
    - Verdict Value: `malicious`
    - Signature Key: `result.signature`
    - Object Type: URLs / Placement: Query Param
    """

    # Trellix IVX invia URL doppiamente encodati (es. %253A → %3A → :)
    # Applichiamo un secondo unquote per normalizzare l'URL prima di analizzarlo.
    url = unquote(url)

    # ── 1. Pre-check whitelist / blacklist ────────────────────────────────────
    match = list_service.check_url(url)
    if match:
        list_type, entry = match
        is_white = list_type == "whitelist"
        return TrellixAnalysisResponse(
            result=TrellixResult(
                verdict="safe" if is_white else "malicious",
                signature=(
                    f"Whitelist-Override: {entry.domain}"
                    if is_white
                    else (
                        f"Blacklist-Override: {entry.domain}"
                        + (f" — {entry.note}" if entry.note else "")
                    )
                ),
                confidence=1.0,
                recommended_action="allow" if is_white else "block",
                reason=(
                    f"Domain '{entry.domain}' is in the operator-managed "
                    f"{'whitelist' if is_white else 'blacklist'}"
                    + (f" ({entry.note})" if entry.note else "")
                ),
            )
        )

    # ── 2. Check cache SQLite ─────────────────────────────────────────────────
    cached = await verdict_cache.get(url)
    if cached:
        sig_parts = cached.risk_indicators[:3]
        signature = " | ".join(sig_parts) if sig_parts else cached.verdict.upper()
        return TrellixAnalysisResponse(
            result=TrellixResult(
                verdict=cached.verdict,
                signature=signature,
                confidence=cached.confidence,
                recommended_action=cached.recommended_action,
                reason=cached.reason,
            )
        )

    # ── 3. Analisi completa Playwright + OpenAI (timeout 55s < Trellix 60s) ───
    try:
        verdict = await asyncio.wait_for(_analyze_simple(url), timeout=55.0)

        await verdict_cache.set(url, verdict)
        await analysis_history.record(url, verdict, source="trellix")

        sig_parts = verdict.risk_indicators[:3]
        signature = " | ".join(sig_parts) if sig_parts else verdict.verdict.upper()

        return TrellixAnalysisResponse(
            result=TrellixResult(
                verdict=verdict.verdict,
                signature=signature,
                confidence=verdict.confidence,
                recommended_action=verdict.recommended_action,
                reason=verdict.reason,
            )
        )

    except asyncio.TimeoutError:
        logger.warning("Trellix analysis timeout for %s", url)
        return TrellixAnalysisResponse(
            result=TrellixResult(
                verdict="suspicious",
                signature="Analysis-Timeout",
                confidence=0.5,
                recommended_action="quarantine",
                reason="Analysis timed out — URL quarantined as precautionary measure",
            )
        )
    except Exception as exc:
        logger.error("Trellix analysis error for %s: %s", url, exc)
        return TrellixAnalysisResponse(
            result=TrellixResult(
                verdict="suspicious",
                signature=f"Analysis-Error: {type(exc).__name__}",
                confidence=0.5,
                recommended_action="quarantine",
                reason=f"Analysis failed ({exc}) — URL quarantined as precautionary measure",
            )
        )


# ── IOC Feed ─────────────────────────────────────────────────────────────────

_SINCE_MAP = {"1h": 1, "24h": 24, "7d": 168, "30d": 720}


@app.get(
    "/ioc",
    tags=["IOC Feed"],
    summary="IOC feed — list of malicious/suspicious URLs for security tools",
)
async def get_ioc_feed(
    verdict: str = Query(
        "all",
        enum=["malicious", "suspicious", "all"],
        description="Filter by verdict type",
    ),
    since: Optional[str] = Query(
        None,
        enum=["1h", "24h", "7d", "30d"],
        description="Filter by analysis time window",
    ),
    format: str = Query(
        "json",
        enum=["json", "txt", "csv"],
        description="Output format: json (SIEM), txt (firewall/proxy, one URL per line), csv",
    ),
    limit: int = Query(1000, ge=1, le=10000, description="Maximum number of entries"),
    _: None = Depends(_require_ioc_token),
):
    since_hours = _SINCE_MAP.get(since) if since else None
    verdicts = ["malicious", "suspicious"] if verdict == "all" else [verdict]
    rows = await verdict_cache.get_ioc_feed(verdicts, since_hours, limit)

    entries = []
    for r in rows:
        full = json.loads(r["full_json"])
        entries.append({
            "url": r["url"],
            "domain": r["domain"],
            "verdict": r["verdict"],
            "confidence": r["confidence"],
            "risk_indicators": full.get("risk_indicators", []),
            "recommended_action": full.get("recommended_action", "block"),
            "analyzed_at": r["analyzed_at"],
            "expires_at": r["expires_at"],
        })

    if format == "txt":
        body = "\n".join(e["url"] for e in entries)
        return PlainTextResponse(content=body, media_type="text/plain")

    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=["url", "domain", "verdict", "confidence",
                        "recommended_action", "analyzed_at", "expires_at"],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(entries)
        return PlainTextResponse(content=output.getvalue(), media_type="text/csv")

    return IOCFeedResponse(
        count=len(entries),
        generated_at=datetime.now(timezone.utc),
        filters={"verdict": verdict, "since": since, "limit": limit},
        entries=[IOCEntry(**e) for e in entries],
    )


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/dashboard/login", tags=["Dashboard"], include_in_schema=False)
async def dashboard_login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/dashboard/login", tags=["Dashboard"], include_in_schema=False)
async def dashboard_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if (
        settings.dashboard_password
        and username == settings.dashboard_username
        and password == settings.dashboard_password
    ):
        request.session["dashboard_user"] = username
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse(request, "login.html", {"error": "Invalid credentials"}, status_code=401)


@app.get("/dashboard/logout", tags=["Dashboard"], include_in_schema=False)
async def dashboard_logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/dashboard/login", status_code=302)


@app.get("/dashboard", tags=["Dashboard"], include_in_schema=False)
async def dashboard(request: Request):
    user = _dashboard_user(request)
    if not user:
        return RedirectResponse(url="/dashboard/login", status_code=302)
    return templates.TemplateResponse(request, "dashboard.html", {"user": user})


@app.get("/dashboard/api/stats", tags=["Dashboard"])
async def dashboard_stats(request: Request):
    _require_dashboard_auth(request)
    return await analysis_history.get_stats()


@app.get("/dashboard/api/analyses", tags=["Dashboard"])
async def dashboard_analyses(
    request: Request,
    verdict: Optional[str] = Query(None),
    since: Optional[str] = Query(None, enum=["1h", "24h", "7d", "30d"]),
    q: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
):
    _require_dashboard_auth(request)
    since_hours = _SINCE_MAP.get(since) if since else None
    return await analysis_history.get_recent(
        verdict=verdict, since_hours=since_hours, domain=q, page=page
    )


@app.delete("/dashboard/api/cache", tags=["Dashboard"])
async def dashboard_invalidate_cache(request: Request, url: str = Query(...)):
    _require_dashboard_auth(request)
    removed = await verdict_cache.remove_url(url)
    return {"removed": removed, "url": url}


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        workers=settings.n_workers,
        jobs_in_queue=get_queue().qsize(),
    )
