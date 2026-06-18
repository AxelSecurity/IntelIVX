from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel


class JobStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class SSLInfo(BaseModel):
    is_http: bool = False
    protocol: Optional[str] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    days_until_expiry: Optional[int] = None
    recently_issued: bool = False
    is_self_signed: bool = False
    error: Optional[str] = None


class PlaywrightResult(BaseModel):
    url: str
    final_url: str
    redirect_count: int
    redirect_chain: list[str] = []
    page_title: str
    has_login_form: bool
    has_password_field: bool
    has_file_download: bool
    external_scripts: list[str]
    suspicious_keywords: list[str]
    ocr_detected_text: str = ""     # Testo estratto via OCR dal viewport (include testo in loghi/immagini)
    load_time_ms: int
    ssl_info: Optional[SSLInfo] = None
    screenshot_base64: Optional[str] = None
    error: Optional[str] = None


class URLVerdict(BaseModel):
    url: str
    verdict: str  # "safe" | "suspicious" | "malicious"
    confidence: float
    risk_indicators: list[str]
    reason: str
    recommended_action: str  # "allow" | "quarantine" | "block"
    ssl_info: Optional[SSLInfo] = None
    chain_verdicts: list["URLVerdict"] = []


URLVerdict.model_rebuild()


class Job(BaseModel):
    job_id: str
    status: JobStatus = JobStatus.pending
    created_at: datetime
    completed_at: Optional[datetime] = None
    urls: list[str]
    callback_url: Optional[str] = None
    results: list[URLVerdict] = []
    errors: list[str] = []
