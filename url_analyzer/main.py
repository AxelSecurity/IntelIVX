import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Optional
from urllib.parse import unquote

from fastapi import Depends, FastAPI, HTTPException, Query, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from url_analyzer.config import settings
from url_analyzer.models.requests import ListEntryRequest, URLAnalysisRequest
from url_analyzer.models.responses import (
    HealthResponse,
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

_worker_tasks = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    await playwright_service.start()
    logger.info("Playwright browser started")

    await list_service.load()
    logger.info("Whitelist/Blacklist loaded")

    await verdict_cache.init()
    logger.info("Verdict cache initialized")

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


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        workers=settings.n_workers,
        jobs_in_queue=get_queue().qsize(),
    )
