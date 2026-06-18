import asyncio
import uuid
from datetime import datetime, timezone
from typing import Optional

from url_analyzer.models.job import Job, JobStatus
from url_analyzer.models.requests import URLAnalysisRequest
from url_analyzer.storage.job_store import job_store

_queue: asyncio.Queue[Job] = asyncio.Queue()


def get_queue() -> asyncio.Queue[Job]:
    return _queue


async def create_job(request: URLAnalysisRequest) -> Job:
    job = Job(
        job_id=str(uuid.uuid4()),
        status=JobStatus.pending,
        created_at=datetime.now(timezone.utc),
        urls=[str(u) for u in request.urls],
        callback_url=str(request.callback_url) if request.callback_url else None,
    )
    await job_store.save(job)

    if request.priority == "high":
        # For high priority, put at the front by draining and re-filling.
        # Simple approach: use a separate high-priority pass in the worker.
        # For now, high priority jobs are just enqueued normally but flagged.
        await _queue.put(job)
    else:
        await _queue.put(job)

    return job


async def get_job(job_id: str) -> Optional[Job]:
    return await job_store.get(job_id)


async def cancel_job(job_id: str) -> bool:
    job = await job_store.get(job_id)
    if job is None:
        return False
    if job.status == JobStatus.pending:
        await job_store.update_status(job_id, JobStatus.failed)
        await job_store.append_error(job_id, "Job cancelled by user")
        return True
    return False
