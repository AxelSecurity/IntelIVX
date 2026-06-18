from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from url_analyzer.models.job import JobStatus, URLVerdict


class ListEntryResponse(BaseModel):
    domain: str
    note: Optional[str] = None
    added_at: datetime


class ListResponse(BaseModel):
    list_type: str
    entries: list[ListEntryResponse]
    count: int


class JobCreatedResponse(BaseModel):
    job_id: str
    status: JobStatus
    urls_count: int


class JobStatusResponse(BaseModel):
    job_id: str
    status: JobStatus
    created_at: datetime
    completed_at: Optional[datetime] = None
    urls_count: int
    results: list[URLVerdict] = []
    errors: list[str] = []


class HealthResponse(BaseModel):
    status: str
    workers: int
    jobs_in_queue: int


class TrellixResult(BaseModel):
    verdict: str
    signature: str
    confidence: float
    recommended_action: str
    reason: str


class TrellixAnalysisResponse(BaseModel):
    result: TrellixResult
