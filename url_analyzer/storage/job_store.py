import asyncio
from datetime import datetime, timezone
from typing import Optional

from url_analyzer.models.job import Job, JobStatus, URLVerdict


class JobStore:
    def __init__(self, ttl_seconds: int = 3600) -> None:
        self._jobs: dict[str, Job] = {}
        self._ttl = ttl_seconds
        self._lock = asyncio.Lock()

    async def save(self, job: Job) -> None:
        async with self._lock:
            self._jobs[job.job_id] = job

    async def get(self, job_id: str) -> Optional[Job]:
        async with self._lock:
            return self._jobs.get(job_id)

    async def update_status(self, job_id: str, status: JobStatus) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job.status = status
                if status in (JobStatus.completed, JobStatus.failed):
                    job.completed_at = datetime.now(timezone.utc)

    async def append_result(self, job_id: str, verdict: URLVerdict) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job.results.append(verdict)

    async def append_error(self, job_id: str, error: str) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job.errors.append(error)

    async def delete(self, job_id: str) -> bool:
        async with self._lock:
            if job_id in self._jobs:
                del self._jobs[job_id]
                return True
            return False

    async def cleanup_expired(self) -> None:
        now = datetime.now(timezone.utc)
        async with self._lock:
            expired = [
                jid
                for jid, job in self._jobs.items()
                if job.completed_at
                and (now - job.completed_at).total_seconds() > self._ttl
            ]
            for jid in expired:
                del self._jobs[jid]

    def queue_size(self) -> int:
        return sum(1 for j in self._jobs.values() if j.status == JobStatus.pending)


job_store = JobStore()
