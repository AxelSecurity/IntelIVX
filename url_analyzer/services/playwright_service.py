import base64
import io
import logging
import re
import time
from datetime import datetime, timezone
from typing import Optional

from playwright.async_api import async_playwright, Browser, BrowserContext, Page, TimeoutError as PWTimeout

from url_analyzer.config import settings
from url_analyzer.models.job import PlaywrightResult, SSLInfo

logger = logging.getLogger(__name__)

try:
    import pytesseract
    from PIL import Image as PilImage
    _TESSERACT_AVAILABLE = True
except ImportError:
    _TESSERACT_AVAILABLE = False

SUSPICIOUS_KEYWORDS = [
    "verify your account",
    "confirm your identity",
    "update your payment",
    "your account has been",
    "click here to unsubscribe",
    "enter your password",
    "sign in to continue",
    "limited time offer",
    "act now",
    "urgent",
]

BROWSER_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
]

# Timeout (ms) per redirect immediati (meta-refresh, JS sincrono, HTTP 3xx)
JS_REDIRECT_WAIT_MS = 3000

# Timeout (ms) aggiuntivo per redirect differiti (setTimeout-based).
# Dopo networkidle, se l'URL non è cambiato, aspettiamo ancora questo tempo
# per catturare redirect attivati da timer JS (es. setTimeout(fn, 1000)).
DEFERRED_REDIRECT_WAIT_MS = 4000

# Timeout (ms) per attendere il settle della catena dopo un redirect differito.
CHAIN_SETTLE_WAIT_MS = 4000


class PlaywrightService:
    def __init__(self) -> None:
        self._browser: Optional[Browser] = None
        self._pw = None

    async def start(self) -> None:
        self._pw = await async_playwright().start()
        self._browser = await self._pw.chromium.launch(args=BROWSER_ARGS, headless=True)

    async def stop(self) -> None:
        if self._browser:
            await self._browser.close()
        if self._pw:
            await self._pw.stop()

    async def analyze(self, url: str) -> PlaywrightResult:
        context: BrowserContext = await self._browser.new_context(
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
        )
        page: Page = await context.new_page()

        # Cattura TUTTE le navigazioni del frame principale:
        # - redirect HTTP (3xx)
        # - <meta http-equiv="refresh">
        # - window.location.href = "..."
        # - window.location.replace(...)
        navigation_chain: list[str] = []

        def on_framenavigated(frame) -> None:
            try:
                if frame == page.main_frame:
                    nav_url = frame.url
                    if nav_url and nav_url not in ("about:blank", ""):
                        navigation_chain.append(nav_url)
            except Exception:
                pass

        page.on("framenavigated", on_framenavigated)

        start_ms = time.monotonic()
        error_msg: Optional[str] = None
        final_url = url
        response = None

        try:
            response = await page.goto(
                url,
                timeout=settings.playwright_timeout_ms,
                wait_until="domcontentloaded",
            )

            # ── Fase 1: redirect immediati (meta-refresh, JS sincrono, HTTP 3xx) ──────
            # networkidle si attiva quando non ci sono connessioni attive per 500ms.
            # Cattura i redirect che avvengono durante il caricamento della pagina.
            try:
                await page.wait_for_load_state(
                    "networkidle",
                    timeout=JS_REDIRECT_WAIT_MS,
                )
            except Exception:
                pass  # timeout networkidle non è fatale

            # ── Fase 2: redirect differiti (setTimeout-based) ─────────────────────────
            # Se networkidle scatta PRIMA che un timer JS (es. setTimeout(fn, 1000))
            # esegua il redirect, l'URL è ancora quello originale.
            # In quel caso aspettiamo esplicitamente che l'URL cambi.
            if page.url == url:
                try:
                    await page.wait_for_url(
                        lambda u: u != url,
                        timeout=DEFERRED_REDIRECT_WAIT_MS,
                    )
                    # Redirect differito rilevato: aspettiamo che l'intera catena si stabilizzi
                    # (es. redirect multipli attivati dalla pagina intermedia)
                    try:
                        await page.wait_for_load_state(
                            "networkidle",
                            timeout=CHAIN_SETTLE_WAIT_MS,
                        )
                    except Exception:
                        pass
                except Exception:
                    pass  # Nessun redirect differito entro il timeout

            final_url = page.url
        except PWTimeout:
            error_msg = f"Timeout after {settings.playwright_timeout_ms}ms"
        except Exception as exc:
            error_msg = str(exc)

        load_time_ms = int((time.monotonic() - start_ms) * 1000)

        # ── Verifica certificato SSL ─────────────────────────────────────────
        # ignore_https_errors=True consente di connettersi anche a certificati
        # scaduti/invalidi e di ottenerne i metadati tramite security_details().
        ssl_info: Optional[SSLInfo] = None
        try:
            if final_url.startswith("http://"):
                ssl_info = SSLInfo(is_http=True)
            elif response is not None:
                sec = await response.security_details()
                if sec:
                    valid_from_ts: float = sec.get("validFrom", 0) or 0
                    valid_to_ts: float = sec.get("validTo", 0) or 0
                    now: float = datetime.now(timezone.utc).timestamp()

                    days_until_expiry = (
                        int((valid_to_ts - now) / 86400) if valid_to_ts else None
                    )
                    days_since_issued = (
                        int((now - valid_from_ts) / 86400) if valid_from_ts else None
                    )
                    recently_issued = bool(
                        days_since_issued is not None and days_since_issued < 30
                    )
                    issuer: str = sec.get("issuer", "") or ""
                    subject: str = sec.get("subjectName", "") or ""
                    is_self_signed: bool = bool(
                        issuer and subject and issuer == subject
                    )

                    ssl_info = SSLInfo(
                        is_http=False,
                        protocol=sec.get("protocol") or None,
                        issuer=issuer or None,
                        subject=subject or None,
                        valid_from=(
                            datetime.fromtimestamp(valid_from_ts, tz=timezone.utc).isoformat()
                            if valid_from_ts else None
                        ),
                        valid_to=(
                            datetime.fromtimestamp(valid_to_ts, tz=timezone.utc).isoformat()
                            if valid_to_ts else None
                        ),
                        days_until_expiry=days_until_expiry,
                        recently_issued=recently_issued,
                        is_self_signed=is_self_signed,
                    )
                else:
                    ssl_info = SSLInfo(error="no_security_details")
        except Exception as exc:
            ssl_info = SSLInfo(error=str(exc))

        # ── Analisi contenuto pagina ─────────────────────────────────────────
        page_title = ""
        has_login_form = False
        has_password_field = False
        has_file_download = False
        external_scripts: list[str] = []
        external_links: list[str] = []
        found_keywords: list[str] = []
        screenshot_b64: Optional[str] = None
        ocr_text: str = ""
        screenshot_b64: Optional[str] = None

        if not error_msg:
            try:
                page_title = await page.title()

                has_password_field = await page.locator("input[type=password]").count() > 0
                has_login_form = has_password_field or await page.locator("form").count() > 0

                download_links = await page.locator(
                    "a[href$='.exe'], a[href$='.zip'], a[href$='.msi'], a[href$='.dmg']"
                ).count()
                has_file_download = download_links > 0

                script_handles = await page.eval_on_selector_all(
                    "script[src]",
                    "els => els.map(e => e.getAttribute('src'))",
                )
                origin = await page.evaluate("() => window.location.origin")
                external_scripts = [
                    s for s in script_handles if s and not s.startswith(origin)
                ]

                # Estrai link esterni per rilevare pagine "ponte" verso phishing.
                # Copre tre pattern comuni: <a href>, onclick, e data-url.
                raw_links: list[str] = []

                # Pattern 1: <a href="...">
                a_handles = await page.eval_on_selector_all(
                    "a[href]",
                    "els => els.map(e => e.getAttribute('href'))",
                )
                raw_links.extend(a_handles)

                # Pattern 2: onclick="window.location='...'" o onclick="location.href='...'"
                onclick_handles = await page.eval_on_selector_all(
                    "[onclick]",
                    "els => els.map(e => e.getAttribute('onclick'))",
                )
                for oc in onclick_handles:
                    if oc:
                        urls = re.findall(
                            r"""(?:location\.href|window\.location|location)\s*=\s*['"]([^'"]+)['"]""",
                            oc,
                        )
                        raw_links.extend(urls)

                # Pattern 3: data-url, data-href, data-link (framework common)
                for attr in ("data-url", "data-href", "data-link"):
                    handles = await page.eval_on_selector_all(
                        f"[{attr}]",
                        f"els => els.map(e => e.getAttribute('{attr}'))",
                    )
                    raw_links.extend(handles)

                external_links: list[str] = []
                seen_external: set[str] = set()
                for href in raw_links:
                    if not href or not isinstance(href, str):
                        continue
                    href = href.strip()
                    if not href.startswith(("http://", "https://")):
                        continue
                    if href.startswith(origin):
                        continue
                    key = href.lower().rstrip("/")
                    if key not in seen_external:
                        seen_external.add(key)
                        external_links.append(href)

                logger.info(
                    "Extracted %d external links for %s: %s",
                    len(external_links), url, external_links[:5],
                )

                body_text = (await page.locator("body").inner_text()).lower()
                found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in body_text]

                # Screenshot per output utente e/o OCR
                needs_screenshot = settings.playwright_screenshot or (
                    settings.playwright_ocr and _TESSERACT_AVAILABLE
                )
                if needs_screenshot:
                    try:
                        raw = await page.screenshot(type="png", full_page=False)

                        if settings.playwright_screenshot:
                            screenshot_b64 = base64.b64encode(raw).decode()

                        if settings.playwright_ocr and _TESSERACT_AVAILABLE:
                            img = PilImage.open(io.BytesIO(raw))
                            if img.width > 1280:
                                ratio = 1280 / img.width
                                img = img.resize(
                                    (1280, int(img.height * ratio)),
                                    PilImage.LANCZOS,
                                )
                            try:
                                raw_ocr = pytesseract.image_to_string(
                                    img, lang="ita+eng", timeout=8
                                )
                                words = re.findall(r"[A-Za-zÀ-ÖØ-öø-ÿ]{3,}", raw_ocr)
                                seen_ocr: set[str] = set()
                                unique_words: list[str] = []
                                for w in words:
                                    key = w.lower()
                                    if key not in seen_ocr:
                                        seen_ocr.add(key)
                                        unique_words.append(w)
                                ocr_text = " ".join(unique_words)
                            except Exception as exc:
                                logger.warning("OCR failed: %s", exc)
                    except Exception as exc:
                        logger.warning("Screenshot/OCR failed: %s", exc)

            except Exception as exc:
                error_msg = f"Post-load analysis error: {exc}"

        await context.close()

        return PlaywrightResult(
            url=url,
            final_url=final_url,
            redirect_count=max(0, len(navigation_chain) - 1),
            redirect_chain=navigation_chain,
            page_title=page_title,
            has_login_form=has_login_form,
            has_password_field=has_password_field,
            has_file_download=has_file_download,
            external_scripts=external_scripts[:20],
            external_links=external_links[:20],
            suspicious_keywords=found_keywords,
            ocr_detected_text=ocr_text,
            load_time_ms=load_time_ms,
            ssl_info=ssl_info,
            screenshot_base64=screenshot_b64,
            error=error_msg,
        )


playwright_service = PlaywrightService()
