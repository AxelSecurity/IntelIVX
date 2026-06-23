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


class IOCEntry(BaseModel):
    url: str
    domain: str
    verdict: str
    confidence: float
    risk_indicators: list[str]
    recommended_action: str
    analyzed_at: datetime
    expires_at: datetime


class IOCFeedResponse(BaseModel):
    count: int
    generated_at: datetime
    filters: dict
    entries: list[IOCEntry]


class TrellixResult(BaseModel):
    verdict: str
    signature: str
    confidence: float
    recommended_action: str
    reason: str


class TrellixAnalysisResponse(BaseModel):
    result: TrellixResult
