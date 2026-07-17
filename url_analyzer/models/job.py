from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel


class JobStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class AiTMSignals(BaseModel):
    # Segnale 1 — Redirect chain tokenizzata
    tokenized_redirect_chain: bool = False
    tokenized_chain_details: str = ""

    # Segnale 2 — Payload offuscato (entropia alta + pochi form)
    high_entropy_payload: bool = False
    shannon_entropy: float = 0.0

    # Segnale 3 — CDN Microsoft clonato su dominio estraneo
    microsoft_cdn_cloning: bool = False
    cloned_cdn_paths: list[str] = []

    # Segnale 4 — Me.htm whitelist patchata (JSH/JSHP + domini estranei)
    me_htm_patched: bool = False
    me_htm_foreign_domains: list[str] = []

    # Segnale 5 — Sottodominio helper separato
    helper_subdomain: bool = False
    helper_domain: str = ""

    # Segnale 6 — Content bridge (PDF/document viewer usato per phishing)
    content_bridge: bool = False
    content_bridge_type: str = ""         # "pdf" | "document" | "file-share"
    pdf_links: list[str] = []             # link estratti dal PDF scaricato


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
    external_links: list[str] = []     # href link esterni (puntano a dominio diverso dall'origine)
    aitm_signals: AiTMSignals = AiTMSignals()  # detection phishing AiTM Microsoft/Entra ID
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
    external_links: list[str] = []  # link esterni trovati nella pagina (per IOC feed)


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
