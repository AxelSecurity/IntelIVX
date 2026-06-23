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

DB_PATH = "data/verdict_cache.db"

# TTL in giorni per tipo di verdetto.
# malicious: lungo — un dominio phishing rimane tale a lungo.
# suspicious: breve — potrebbe evolversi, meglio rivalutare.
# safe: medio — domini legittimi stabili ma non per sempre.
TTL_DAYS: dict[str, int] = {
    "malicious": 30,
    "suspicious": 3,
    "safe": 7,
}

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS verdict_cache (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT NOT NULL UNIQUE,
    domain      TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    confidence  REAL NOT NULL,
    full_json   TEXT NOT NULL,
    analyzed_at TEXT NOT NULL,
    expires_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_url     ON verdict_cache(url);
CREATE INDEX IF NOT EXISTS idx_domain  ON verdict_cache(domain);
CREATE INDEX IF NOT EXISTS idx_expires ON verdict_cache(expires_at);
"""


def _normalize(url: str) -> str:
    return url.strip().rstrip("/").lower()


class VerdictCache:
    def __init__(self, db_path: str = DB_PATH) -> None:
        self._db_path = db_path
        self._lock = asyncio.Lock()

    async def init(self) -> None:
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        async with aiosqlite.connect(self._db_path) as db:
            await db.executescript(_CREATE_SQL)
            await db.commit()
        logger.info("Verdict cache initialized: %s", self._db_path)

    async def get(self, url: str) -> Optional[URLVerdict]:
        """Restituisce il verdetto dalla cache se presente e non scaduto."""
        normalized = _normalize(url)
        now = datetime.now(timezone.utc).isoformat()
        async with aiosqlite.connect(self._db_path) as db:
            async with db.execute(
                "SELECT full_json FROM verdict_cache WHERE url = ? AND expires_at > ?",
                (normalized, now),
            ) as cursor:
                row = await cursor.fetchone()
        if row:
            logger.info("Cache HIT: %s", url)
            return URLVerdict(**json.loads(row[0]))
        logger.debug("Cache MISS: %s", url)
        return None

    async def set(self, url: str, verdict: URLVerdict) -> None:
        """Salva il verdetto con TTL basato sul tipo.
        I verdetti 'safe' non vengono cachati: ogni URL safe viene sempre ri-analizzato
        per rilevare eventuali compromissioni future.
        """
        if verdict.verdict == "safe":
            logger.debug("Cache SKIP (safe): %s", url)
            return
        normalized = _normalize(url)
        domain = urlparse(url).hostname or ""
        ttl_days = TTL_DAYS.get(verdict.verdict, 7)
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(days=ttl_days)).isoformat()
        full_json = verdict.model_dump_json()

        async with self._lock:
            async with aiosqlite.connect(self._db_path) as db:
                await db.execute(
                    """
                    INSERT INTO verdict_cache
                        (url, domain, verdict, confidence, full_json, analyzed_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(url) DO UPDATE SET
                        verdict     = excluded.verdict,
                        confidence  = excluded.confidence,
                        full_json   = excluded.full_json,
                        analyzed_at = excluded.analyzed_at,
                        expires_at  = excluded.expires_at
                    """,
                    (normalized, domain, verdict.verdict, verdict.confidence,
                     full_json, now.isoformat(), expires_at),
                )
                await db.commit()
        logger.info("Cache SET: %s → %s (TTL %d giorni)", url, verdict.verdict, ttl_days)

    async def remove_url(self, url: str) -> bool:
        """Rimuove un URL dalla cache per forzare una ri-analisi."""
        normalized = _normalize(url)
        async with self._lock:
            async with aiosqlite.connect(self._db_path) as db:
                cursor = await db.execute(
                    "DELETE FROM verdict_cache WHERE url = ?", (normalized,)
                )
                await db.commit()
                removed = cursor.rowcount > 0
        if removed:
            logger.info("Cache INVALIDATED: %s", url)
        return removed

    async def get_ioc_feed(
        self,
        verdicts: list[str],
        since_hours: Optional[int],
        limit: int,
    ) -> list[dict]:
        """
        Restituisce IOC attivi (non scaduti) dal DB SQLite.
        verdicts: es. ["malicious"] o ["malicious", "suspicious"]
        since_hours: None = tutti, 24 = ultime 24h, 168 = ultimi 7 giorni, ecc.
        """
        now = datetime.now(timezone.utc)
        placeholders = ",".join("?" * len(verdicts))
        params: list = [now.isoformat(), *verdicts]

        since_clause = ""
        if since_hours is not None:
            since_dt = (now - timedelta(hours=since_hours)).isoformat()
            since_clause = "AND analyzed_at >= ?"
            params.append(since_dt)

        params.append(limit)

        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                f"""
                SELECT url, domain, verdict, confidence, full_json, analyzed_at, expires_at
                FROM verdict_cache
                WHERE expires_at > ? AND verdict IN ({placeholders})
                {since_clause}
                ORDER BY analyzed_at DESC
                LIMIT ?
                """,
                params,
            ) as cursor:
                rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def cleanup_expired(self) -> int:
        """Rimuove le entry scadute. Chiamata dal cleanup_loop ogni 5 minuti."""
        now = datetime.now(timezone.utc).isoformat()
        async with self._lock:
            async with aiosqlite.connect(self._db_path) as db:
                cursor = await db.execute(
                    "DELETE FROM verdict_cache WHERE expires_at <= ?", (now,)
                )
                await db.commit()
                count = cursor.rowcount
        if count:
            logger.info("Cache cleanup: removed %d expired entries", count)
        return count


verdict_cache = VerdictCache()
