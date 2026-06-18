from typing import Literal, Optional

from pydantic import BaseModel, HttpUrl, field_validator


class ListEntryRequest(BaseModel):
    pattern: str
    note: Optional[str] = None


class URLAnalysisRequest(BaseModel):
    urls: list[HttpUrl]
    callback_url: Optional[HttpUrl] = None
    priority: Literal["normal", "high"] = "normal"

    @field_validator("urls")
    @classmethod
    def urls_not_empty(cls, v: list) -> list:
        if not v:
            raise ValueError("urls must contain at least one URL")
        if len(v) > 50:
            raise ValueError("urls must contain at most 50 URLs per request")
        return v
