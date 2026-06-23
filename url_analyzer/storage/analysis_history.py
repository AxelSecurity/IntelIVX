import asyncio
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

import aiosqlite

from url_analyzer.models.job import URLVerdict

logger = logging.getLogger(__name__)

DB_PATH = "data/verdict_cache.db"  # stesso file SQLite della cache

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS analysis_history (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    url                TEXT NOT NULL,
    domain             TEXT NOT NULL,
    verdict            TEXT NOT NULL,
    confidence         REAL NOT NULL,
    risk_indicators    TEXT NOT NULL,
    reason             TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    final_url          TEXT,
    redirect_count     INTEGER DEFAULT 0,
    source             TEXT DEFAULT 'job',
    analyzed_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hist_analyzed_at ON analysis_history(analyzed_at);
CREATE INDEX IF NOT EXISTS idx_hist_verdict     ON analysis_history(verdict);
CREATE INDEX IF NOT EXISTS idx_hist_domain      ON analysis_history(domain);
"""


class AnalysisHistory:
    def __init__(self, db_path: str = DB_PATH) -> None:
        self._db_path = db_path
        self._lock = asyncio.Lock()

    async def init(self) -> None:
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        async with aiosqlite.connect(self._db_path) as db:
            await db.executescript(_CREATE_SQL)
            await db.commit()
        logger.info("Analysis history initialized")

    async def record(
        self,
        url: str,
        verdict: URLVerdict,
        source: str = "job",
    ) -> None:
        """Registra un'analisi nell'audit log."""
        domain = urlparse(url).hostname or ""
        now = datetime.now(timezone.utc).isoformat()
        risk_json = json.dumps(verdict.risk_indicators)
        final_url = getattr(verdict, "final_url", None) or url
        redirect_count = 0

        async with self._lock:
            async with aiosqlite.connect(self._db_path) as db:
                await db.execute(
                    """
                    INSERT INTO analysis_history
                        (url, domain, verdict, confidence, risk_indicators, reason,
                         recommended_action, final_url, redirect_count, source, analyzed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (url, domain, verdict.verdict, verdict.confidence, risk_json,
                     verdict.reason, verdict.recommended_action, final_url,
                     redirect_count, source, now),
                )
                await db.commit()

    async def get_stats(self) -> dict:
        """Conteggi per verdetto + breakdown ultimi 7 giorni per giorno."""
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row

            # Totali
            async with db.execute(
                "SELECT verdict, COUNT(*) as cnt FROM analysis_history GROUP BY verdict"
            ) as cur:
                rows = await cur.fetchall()
            counts = {r["verdict"]: r["cnt"] for r in rows}

            # Per giorno ultimi 7 giorni
            since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
            async with db.execute(
                """
                SELECT substr(analyzed_at, 1, 10) as day, verdict, COUNT(*) as cnt
                FROM analysis_history
                WHERE analyzed_at >= ?
                GROUP BY day, verdict
                ORDER BY day
                """,
                (since,),
            ) as cur:
                day_rows = await cur.fetchall()

        by_day: dict[str, dict] = {}
        for r in day_rows:
            d = r["day"]
            if d not in by_day:
                by_day[d] = {"malicious": 0, "suspicious": 0, "safe": 0}
            by_day[d][r["verdict"]] = r["cnt"]

        return {
            "total": sum(counts.values()),
            "malicious": counts.get("malicious", 0),
            "suspicious": counts.get("suspicious", 0),
            "safe": counts.get("safe", 0),
            "by_day": [{"day": d, **v} for d, v in sorted(by_day.items())],
        }

    async def get_recent(
        self,
        verdict: Optional[str] = None,
        since_hours: Optional[int] = None,
        domain: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> dict:
        """Lista paginata con filtri."""
        conditions = []
        params: list = []

        if verdict and verdict != "all":
            conditions.append("verdict = ?")
            params.append(verdict)

        if since_hours:
            since = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
            conditions.append("analyzed_at >= ?")
            params.append(since)

        if domain:
            conditions.append("domain LIKE ?")
            params.append(f"%{domain}%")

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        offset = (page - 1) * page_size

        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row

            async with db.execute(
                f"SELECT COUNT(*) as cnt FROM analysis_history {where}", params
            ) as cur:
                total = (await cur.fetchone())["cnt"]

            async with db.execute(
                f"""
                SELECT id, url, domain, verdict, confidence, risk_indicators,
                       reason, recommended_action, redirect_count, source, analyzed_at
                FROM analysis_history {where}
                ORDER BY analyzed_at DESC
                LIMIT ? OFFSET ?
                """,
                params + [page_size, offset],
            ) as cur:
                rows = await cur.fetchall()

        entries = []
        for r in rows:
            entries.append({
                "id": r["id"],
                "url": r["url"],
                "domain": r["domain"],
                "verdict": r["verdict"],
                "confidence": r["confidence"],
                "risk_indicators": json.loads(r["risk_indicators"]),
                "reason": r["reason"],
                "recommended_action": r["recommended_action"],
                "redirect_count": r["redirect_count"],
                "source": r["source"],
                "analyzed_at": r["analyzed_at"],
            })

        return {
            "entries": entries,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": max(1, (total + page_size - 1) // page_size),
        }


analysis_history = AnalysisHistory()
