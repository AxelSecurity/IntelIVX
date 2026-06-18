import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

LISTS_PATH = "lists.json"


def _extract_domain(pattern: str) -> str:
    """Normalizza il pattern: estrae il dominio se è un URL completo, altrimenti lo usa as-is."""
    p = pattern.strip().lower()
    if p.startswith("http://") or p.startswith("https://"):
        return urlparse(p).hostname or p
    return p


class _Entry:
    """Struttura dati interna per un'entry di lista."""
    __slots__ = ("domain", "note", "added_at")

    def __init__(self, domain: str, note: Optional[str], added_at: datetime) -> None:
        self.domain = domain
        self.note = note
        self.added_at = added_at

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "note": self.note,
            "added_at": self.added_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "_Entry":
        added_at = d.get("added_at")
        if isinstance(added_at, str):
            added_at = datetime.fromisoformat(added_at)
        return cls(domain=d["domain"], note=d.get("note"), added_at=added_at)


class ListService:
    def __init__(self, path: str = LISTS_PATH) -> None:
        self._path = path
        self._whitelist: dict[str, _Entry] = {}
        self._blacklist: dict[str, _Entry] = {}
        self._lock = asyncio.Lock()

    async def load(self) -> None:
        try:
            with open(self._path, "r") as f:
                data = json.load(f)
            for e in data.get("whitelist", []):
                entry = _Entry.from_dict(e)
                self._whitelist[entry.domain] = entry
            for e in data.get("blacklist", []):
                entry = _Entry.from_dict(e)
                self._blacklist[entry.domain] = entry
            logger.info(
                "Loaded %d whitelist + %d blacklist entries",
                len(self._whitelist),
                len(self._blacklist),
            )
        except FileNotFoundError:
            logger.info("lists.json not found, starting with empty lists")
        except Exception as exc:
            logger.error("Error loading lists.json: %s", exc)

    async def _save(self) -> None:
        data = {
            "whitelist": [e.to_dict() for e in self._whitelist.values()],
            "blacklist": [e.to_dict() for e in self._blacklist.values()],
        }
        with open(self._path, "w") as f:
            json.dump(data, f, indent=2)

    async def add(self, list_type: str, pattern: str, note: Optional[str] = None) -> _Entry:
        domain = _extract_domain(pattern)
        entry = _Entry(domain=domain, note=note, added_at=datetime.now(timezone.utc))
        async with self._lock:
            target = self._whitelist if list_type == "whitelist" else self._blacklist
            target[domain] = entry
            await self._save()
        return entry

    async def remove(self, list_type: str, pattern: str) -> bool:
        domain = _extract_domain(pattern)
        async with self._lock:
            target = self._whitelist if list_type == "whitelist" else self._blacklist
            if domain not in target:
                return False
            del target[domain]
            await self._save()
        return True

    def get_all(self, list_type: str) -> list[_Entry]:
        target = self._whitelist if list_type == "whitelist" else self._blacklist
        return list(target.values())

    def check_url(self, url: str) -> Optional[tuple[str, _Entry]]:
        """
        Controlla l'URL contro le due liste.
        Ritorna ("blacklist", entry) o ("whitelist", entry) o None.
        La blacklist ha sempre precedenza sulla whitelist.
        """
        try:
            domain = (urlparse(url).hostname or "").lower()
        except Exception:
            return None

        if not domain:
            return None

        if match := self._match_domain(domain, self._blacklist):
            return ("blacklist", match)
        if match := self._match_domain(domain, self._whitelist):
            return ("whitelist", match)
        return None

    @staticmethod
    def _match_domain(domain: str, entries: dict[str, _Entry]) -> Optional[_Entry]:
        for pattern, entry in entries.items():
            if domain == pattern or domain.endswith("." + pattern):
                return entry
        return None


list_service = ListService()
