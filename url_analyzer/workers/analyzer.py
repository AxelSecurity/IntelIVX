import asyncio
import logging

import httpx

from url_analyzer.models.job import Job, JobStatus, URLVerdict
from url_analyzer.services.job_service import get_queue
from url_analyzer.services.list_service import list_service
from url_analyzer.services.openai_service import openai_service
from url_analyzer.services.playwright_service import playwright_service
from url_analyzer.storage.job_store import job_store
from url_analyzer.storage.analysis_history import analysis_history
from url_analyzer.storage.verdict_cache import verdict_cache

logger = logging.getLogger(__name__)

MAX_CHAIN_DEPTH = 5


async def _cache_external_links(verdict: URLVerdict) -> None:
    """Salva nella cache anche gli URL esterni trovati nella pagina,
    così che finiscano nel feed IOC invece della sola pagina ponte."""
    if verdict.verdict not in ("malicious", "suspicious"):
        return
    if not verdict.external_links:
        return
    for ext_url in verdict.external_links:
        ext_verdict = URLVerdict(
            url=ext_url,
            verdict=verdict.verdict,
            confidence=verdict.confidence,
            risk_indicators=[
                f"External link from bridge page: {verdict.url}"
            ],
            reason=(
                f"Destination of external link found on {verdict.url}. "
                f"Original reason: {verdict.reason[:300]}"
            ),
            recommended_action=verdict.recommended_action,
        )
        await verdict_cache.set(ext_url, ext_verdict)
    logger.info(
        "Cached %d external links for IOC feed from %s",
        len(verdict.external_links), verdict.url,
    )


async def _analyze_simple(url: str) -> URLVerdict:
    """
    Analisi rapida: singola sessione Playwright + singola chiamata AI.
    Playwright segue internamente tutti i redirect e si ferma sulla pagina finale.
    Il PlaywrightResult include redirect_count, final_url e tutti i segnali della
    pagina finale — sufficienti per una classificazione accurata.
    Usata dall'endpoint Trellix per rispettare il timeout di 55 secondi.
    """
    pw_result = await playwright_service.analyze(url)
    return await openai_service.analyze(pw_result)


async def _analyze_with_chain(url: str) -> URLVerdict:
    pw_result = await playwright_service.analyze(url)
    main_verdict = await openai_service.analyze(pw_result)

    # redirect_chain[0] is the original URL — skip it, take the rest up to MAX_CHAIN_DEPTH
    chain_urls = pw_result.redirect_chain[1:][:MAX_CHAIN_DEPTH]
    if not chain_urls:
        return main_verdict

    logger.info("Analyzing %d redirect hops for %s", len(chain_urls), url)

    # Analisi parallela degli hop per ridurre la latenza totale
    async def _analyze_hop(hop_url: str) -> URLVerdict | None:
        try:
            hop_pw = await playwright_service.analyze(hop_url)
            return await openai_service.analyze(hop_pw)
        except Exception as exc:
            logger.warning("Chain hop analysis failed for %s: %s", hop_url, exc)
            return None

    results = await asyncio.gather(*[_analyze_hop(u) for u in chain_urls])
    hop_verdicts: list[URLVerdict] = [v for v in results if v is not None]

    if not hop_verdicts:
        return main_verdict  # già passato per _apply_aitm_overrides

    # La sintesi riceve tutti i verdetti (originale + hop) per una valutazione completa,
    # ma chain_verdicts nella risposta mostra solo gli hop (evita duplicazione della URL originale).
    all_verdicts = [main_verdict] + hop_verdicts
    final_verdict = await openai_service.synthesize_chain(all_verdicts)
    final_verdict.ssl_info = main_verdict.ssl_info
    final_verdict.chain_verdicts = hop_verdicts
    final_verdict.external_links = main_verdict.external_links
    return final_verdict


async def _process_job(job: Job) -> None:
    await job_store.update_status(job.job_id, JobStatus.running)

    for url in job.urls:
        try:
            # ── Pre-check whitelist / blacklist ──────────────────────────────
            match = list_service.check_url(url)
            if match:
                list_type, entry = match
                is_white = list_type == "whitelist"
                verdict = URLVerdict(
                    url=url,
                    verdict="safe" if is_white else "malicious",
                    confidence=1.0,
                    risk_indicators=[
                        f"Domain matched {'whitelist' if is_white else 'blacklist'}: {entry.domain}"
                    ],
                    reason=(
                        f"Domain '{entry.domain}' is in the operator-managed "
                        f"{'whitelist' if is_white else 'blacklist'}"
                        + (f" — {entry.note}" if entry.note else "")
                    ),
                    recommended_action="allow" if is_white else "block",
                )
                logger.info("%s matched %s → %s", url, list_type, verdict.recommended_action)
                await analysis_history.record(url, verdict, source=list_type)
                await job_store.append_result(job.job_id, verdict)
                continue
            # ── Check cache SQLite ────────────────────────────────────────────
            cached = await verdict_cache.get(url)
            if cached:
                logger.info("Cache HIT for job: %s → %s", url, cached.verdict)
                await job_store.append_result(job.job_id, cached)
                continue
            # ── Analisi completa Playwright + OpenAI ─────────────────────────
            verdict = await _analyze_with_chain(url)
            await verdict_cache.set(url, verdict)
            await _cache_external_links(verdict)
            await analysis_history.record(url, verdict, source="job")
            await job_store.append_result(job.job_id, verdict)
        except Exception as exc:
            logger.error("Error analyzing %s: %s", url, exc)
            await job_store.append_error(job.job_id, f"{url}: {exc}")

    final_job = await job_store.get(job.job_id)
    if final_job and final_job.status == JobStatus.running:
        await job_store.update_status(job.job_id, JobStatus.completed)

    if job.callback_url:
        await _send_callback(job.job_id, job.callback_url)


async def _send_callback(job_id: str, callback_url: str) -> None:
    job = await job_store.get(job_id)
    if not job:
        return
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(callback_url, json=job.model_dump(mode="json"))
    except Exception as exc:
        logger.warning("Callback to %s failed: %s", callback_url, exc)


async def worker(worker_id: int) -> None:
    queue = get_queue()
    logger.info("Worker %d started", worker_id)
    while True:
        job: Job = await queue.get()
        current = await job_store.get(job.job_id)
        if current is None or current.status == JobStatus.failed:
            queue.task_done()
            continue
        try:
            await _process_job(job)
        except Exception as exc:
            logger.error("Worker %d unhandled error on job %s: %s", worker_id, job.job_id, exc)
            await job_store.update_status(job.job_id, JobStatus.failed)
            await job_store.append_error(job.job_id, str(exc))
        finally:
            queue.task_done()


async def start_workers(n: int) -> list[asyncio.Task]:
    tasks = [asyncio.create_task(worker(i)) for i in range(n)]
    return tasks


async def cleanup_loop(interval_seconds: int = 300) -> None:
    while True:
        await asyncio.sleep(interval_seconds)
        await job_store.cleanup_expired()
        await verdict_cache.cleanup_expired()
        logger.debug("Expired jobs and cache entries cleaned up")
