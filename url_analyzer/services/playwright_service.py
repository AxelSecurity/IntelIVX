import base64
import collections
import io
import logging
import math
import re
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from playwright.async_api import async_playwright, Browser, BrowserContext, Page, TimeoutError as PWTimeout

from url_analyzer.config import settings
from url_analyzer.models.job import AiTMSignals, PlaywrightResult, SSLInfo

logger = logging.getLogger(__name__)

try:
    from PyPDF2 import PdfReader as _PdfReader
    _PDF_SUPPORT = True
except ImportError:
    _PDF_SUPPORT = False

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

# Domini ufficiali Microsoft per il confronto (Segnali 3 e 4 AiTM).
_MS_OFFICIAL_DOMAINS: set[str] = {
    "login.microsoftonline.com", "login.microsoftonline.us",
    "login.microsoftonline.de", "login.microsoftonline.cn",
    "login.live.com", "login.windows.net", "login.windows-ppe.net",
    "login.chinacloudapi.cn", "login.cloudgovapi.us",
    "login.microsoft.com", "login.microsoft.us",
    "account.microsoft.com", "account.live.com",
    "aadcdn.msauth.net", "aadcdn.msauth.cn",
    "aadcdn.msftauth.net", "aadcdn.msftauth.cn",
    "aadcdn.msftauthimages.net",
    "graph.microsoft.com", "graph.microsoft.us",
    "sts.windows.net", "autologon.microsoft.com",
    "msft.sts.microsoft.com",
}

# Pattern path CDN Microsoft per rilevare clonazione (Segnale 3).
_MS_CDN_PATH_PATTERNS: list[str] = [
    "/cdn/msauth/",
    "/cdn/msftauth/",
    "ests/2.1/content/cdnbundles/",
    "ests/2.1/content/js/",
    "msauth/shared/1.0/content/js/",
    "msauth/shared/1.0/content/images/",
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


# ── AiTM detection helpers ──────────────────────────────────────────────────────

def _shannon_entropy(text: str) -> float:
    """Entropia di Shannon di una stringa (bit per carattere)."""
    if not text:
        return 0.0
    n = len(text)
    counter = collections.Counter(text)
    return -sum((v / n) * math.log2(v / n) for v in counter.values())


def _extract_apex(host: str) -> str:
    """Estrae il dominio apex (ultimi 2 segmenti) da un hostname."""
    parts = host.rsplit(".", 2)
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _parse_url_for_chain_analysis(url_str: str) -> tuple[str, str, dict[str, str]]:
    """Ritorna (host, path, query_params) da una URL."""
    try:
        p = urlparse(url_str)
        host = p.hostname or ""
        path = p.path or ""
        qp: dict[str, str] = {}
        if p.query:
            for pair in p.query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    qp[k] = v
                else:
                    qp[pair] = ""
        return host, path, qp
    except Exception:
        return "", "", {}


def _detect_tokenized_redirect(redirect_chain: list[str]) -> tuple[bool, str]:
    """Segnale 1: 2+ hop sullo stesso apex con token a entropia crescente."""
    if len(redirect_chain) < 2:
        return False, ""

    hosts: list[str] = []
    params_list: list[dict[str, str]] = []
    token_lengths: list[int] = []

    for url_str in redirect_chain:
        host, path, qp = _parse_url_for_chain_analysis(url_str)
        hosts.append(host)
        params_list.append(qp)
        # Prendi il valore del param più lungo come "token"
        longest = max(qp.values(), key=len) if qp else ""
        token_lengths.append(len(longest))

    apexes = [_extract_apex(h) for h in hosts]

    # Controlla: almeno 2 diversi host sullo stesso apex
    unique_hosts_on_same_apex = len(set(hosts))
    unique_apexes = len(set(apexes))

    detail_parts: list[str] = []

    # Check: 2+ hop con stesso apex
    if unique_apexes == 1 and unique_hosts_on_same_apex >= 2:
        detail_parts.append(f"{unique_hosts_on_same_apex} hosts on same apex ({apexes[0]})")

    # Check: token length cresce attraverso gli hop
    growing = all(
        token_lengths[i] >= token_lengths[i - 1] and token_lengths[i] > 0
        for i in range(1, len(token_lengths))
    )
    if growing and token_lengths[-1] > 20:
        detail_parts.append(
            f"token length growing: {'→'.join(str(n) for n in token_lengths)}"
        )

    # Check: i path contengono segmenti alfanumerici tipo ID
    path_segments = [
        re.findall(r"/([a-zA-Z0-9_-]{8,})/", _parse_url_for_chain_analysis(u)[1])
        for u in redirect_chain
    ]
    has_id_segments = any(segs for segs in path_segments)

    if has_id_segments:
        detail_parts.append("path contains ID-like segments")

    if len(detail_parts) >= 2:
        return True, "; ".join(detail_parts)
    if len(detail_parts) == 1 and growing:
        return True, detail_parts[0]
    return False, "; ".join(detail_parts) if detail_parts else ""


def _detect_high_entropy(body_text: str) -> tuple[bool, float]:
    """Segnale 2: entropia di Shannon > 5.5 su una pagina con pochi form."""
    entropy = _shannon_entropy(body_text)
    triggered = entropy > 5.5
    return triggered, round(entropy, 2)


def _detect_ms_cdn_cloning(
    external_scripts: list[str], final_url: str
) -> tuple[bool, list[str]]:
    """Segnale 3: path CDN Microsoft su hostname non ufficiale."""
    final_host = urlparse(final_url).hostname or ""
    if final_host in _MS_OFFICIAL_DOMAINS:
        return False, []  # è un dominio Microsoft legittimo

    cloned: list[str] = []
    for script_url in external_scripts:
        p = urlparse(script_url)
        script_host = p.hostname or ""
        if script_host in _MS_OFFICIAL_DOMAINS:
            continue  # il CDN è servito da Microsoft stesso — ok
        script_path = p.path or ""
        for pattern in _MS_CDN_PATH_PATTERNS:
            if pattern in script_path:
                cloned.append(script_url)
                break

    return len(cloned) > 0, cloned[:5]


def _detect_me_htm_patch(
    page_content: str, page_title: str
) -> tuple[bool, list[str]]:
    """Segnale 4: rileva lo script Me.htm di Microsoft con origin whitelist patchata."""
    if "JSH" not in page_content and "JSHP" not in page_content:
        return False, []

    # Cerca un array di origin whitelist nel contenuto della pagina:
    # pattern: tipo "prod":"https://login.windows-ppe.net", colonna:valore
    origin_matches = re.findall(
        r"""["'](?:prod|int|dev|ppe|test|staging)["']\s*:\s*["']https?://([^"']+)["']""",
        page_content,
        re.IGNORECASE,
    )
    if not origin_matches:
        return False, []

    foreign: list[str] = []
    for domain in origin_matches:
        d = domain.lower()
        # Controlla se il dominio o un suo suffisso è nella allowlist Microsoft
        is_ms = d in _MS_OFFICIAL_DOMAINS or any(
            d.endswith("." + ms) for ms in _MS_OFFICIAL_DOMAINS
        )
        if not is_ms:
            foreign.append(d)

    return len(foreign) > 0, list(set(foreign))


def _detect_helper_subdomain(
    redirect_chain: list[str],
) -> tuple[bool, str]:
    """Segnale 5: sottodominio random sullo stesso apex usato come helper."""
    if len(redirect_chain) < 2:
        return False, ""

    hosts = []
    for url_str in redirect_chain:
        h = urlparse(url_str).hostname or ""
        hosts.append(h)

    apexes = [_extract_apex(h) for h in hosts]
    main_apex = apexes[-1]  # apex del landing finale

    for host in hosts[:-1]:
        apex = _extract_apex(host)
        if apex == main_apex and host != hosts[-1]:
            # Sottodominio sullo stesso apex, diverso dal landing
            parts = host.split(f".{apex}")[0]
            if len(parts) > 3 and any(c.isdigit() or re.match(r"[a-f0-9]+", parts) for c in parts[:8]):
                return True, host

    return False, ""


# ── PDF extraction ────────────────────────────────────────────────────────────

def _extract_links_from_pdf(pdf_data: bytes) -> list[str]:
    """Estrae URL dal contenuto di un PDF usando PyPDF2."""
    if not _PDF_SUPPORT:
        return []
    links: list[str] = []
    try:
        reader = _PdfReader(io.BytesIO(pdf_data))
        for page_num in range(min(len(reader.pages), 10)):
            page = reader.pages[page_num]
            # Estrai annotazioni link (/A o /URI)
            if "/Annots" in page:
                try:
                    annots = page["/Annots"]
                    for annot in annots if isinstance(annots, list) else [annots]:
                        obj = annot.get_object() if hasattr(annot, "get_object") else annot
                        if isinstance(obj, dict):
                            a = obj.get("/A", {})
                            if isinstance(a, dict):
                                uri = a.get("/URI")
                                if uri and isinstance(uri, str):
                                    links.append(uri)
                except Exception:
                    pass
            # Estrai anche dal testo con regex URL
            text = page.extract_text() or ""
            found = re.findall(r"https?://[^\s)]+", text)
            links.extend(found)
    except Exception as exc:
        logger.warning("PDF parsing failed: %s", exc)

    return list(set(links))


def _detect_content_bridge(page_title: str, url: str) -> tuple[bool, str]:
    """Rileva se la pagina è un visualizzatore PDF o bridge di file sharing."""
    combined = f"{page_title.lower()} {url.lower()}"
    if ".pdf" in combined or "pdf" in page_title.lower():
        return True, "pdf"
    # Piattaforme note di file sharing / document viewing
    bridge_patterns = [
        "tagbox.io", "docs.google.com", "onedrive.live.com", "dropbox.com",
        "box.com/s/", "wetransfer.com", "sharepoint.com", "filebin.net",
        "docdroid", "docdro.id", "scribd.com", "issuu.com", "fliphtml5",
        "viewer", "preview", "file-share", "document",
    ]
    for pattern in bridge_patterns:
        if pattern in combined:
            return True, "file-share"
    return False, ""


# ── PlaywrightService ──────────────────────────────────────────────────────────

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

        # Cattura risposte PDF via event listener (non-bloccante, zero overhead)
        pdf_bodies: list[bytes] = []

        async def _on_response(response) -> None:
            try:
                ct = response.headers.get("content-type", "")
                url_lower = response.url.lower()
                if "application/pdf" in ct or url_lower.endswith(".pdf"):
                    try:
                        body = await response.body()
                        pdf_bodies.append(body)
                    except Exception:
                        pass
            except Exception:
                pass

        page.on("response", _on_response)

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

        # ── AiTM detection ────────────────────────────────────────────────────
        aitm = AiTMSignals()

        # Segnale 1 — Redirect chain tokenizzata
        tok_detected, tok_detail = _detect_tokenized_redirect(navigation_chain)
        aitm.tokenized_redirect_chain = tok_detected
        aitm.tokenized_chain_details = tok_detail

        # Segnale 2 — Payload offuscato (entropia + pochi form)
        if not error_msg and body_text:
            high_ent, ent_val = _detect_high_entropy(body_text)
            # Rafforza: se entropia alta E nessun form → più forte
            form_count = await page.locator("form").count() if not error_msg else 0
            input_count = await page.locator("input").count() if not error_msg else 0
            aitm.high_entropy_payload = high_ent and form_count == 0 and input_count < 3
            aitm.shannon_entropy = ent_val

        # Segnale 3 — CDN Microsoft clonato su dominio estraneo
        cdn_detected, cdn_paths = _detect_ms_cdn_cloning(external_scripts, final_url)
        aitm.microsoft_cdn_cloning = cdn_detected
        aitm.cloned_cdn_paths = cdn_paths

        # Segnale 4 — Me.htm whitelist patchata (JSH/JSHP + domini estranei)
        if not error_msg:
            script_texts = await page.eval_on_selector_all(
                "script:not([src])",
                "els => els.map(e => e.textContent || '').filter(t => t.length > 0)",
            )
            combined_scripts = "\n".join(script_texts)
            # Unisci anche inner_text della pagina per catturare script inline
            page_content = combined_scripts + "\n" + (await page.locator("body").inner_text() or "")
            me_patched, me_foreign = _detect_me_htm_patch(
                page_content, page_title
            )
            aitm.me_htm_patched = me_patched
            aitm.me_htm_foreign_domains = me_foreign

        # Segnale 5 — Sottodominio helper sullo stesso apex
        helper_detected, helper_domain = _detect_helper_subdomain(navigation_chain)
        aitm.helper_subdomain = helper_detected
        aitm.helper_domain = helper_domain

        # Segnale 6 — Content bridge (PDF/document viewer) + estrazione link da PDF
        bridge_detected, bridge_type = _detect_content_bridge(page_title, url)
        aitm.content_bridge = bridge_detected
        aitm.content_bridge_type = bridge_type

        # Estrai link dai PDF catturati durante la navigazione (response listener)
        pdf_links: list[str] = []
        if bridge_detected and pdf_bodies:
            for pdf_data in pdf_bodies:
                links = _extract_links_from_pdf(pdf_data)
                if links:
                    logger.info(
                        "Extracted %d links from PDF on %s: %s",
                        len(links), url, links[:5],
                    )
                pdf_links.extend(links)

        # Se PDF viewer ma nessuna risposta PDF catturata (es. caricamento blob JS),
        # prova a estrarre link dal DOM renderizzato dal viewer
        if bridge_detected and not pdf_links and not error_msg:
            try:
                # Cerca link aggiunti dinamicamente dal visualizzatore PDF
                extra_dom_links = await page.eval_on_selector_all(
                    "a[href^='http']",
                    "els => els.map(e => e.getAttribute('href'))",
                )
                for link in extra_dom_links:
                    if link and not link.startswith(origin):
                        pdf_links.append(link)
                if extra_dom_links:
                    logger.info(
                        "Extracted %d extra DOM links from PDF viewer on %s: %s",
                        len(extra_dom_links), url, extra_dom_links[:5],
                    )
            except Exception:
                pass

        aitm.pdf_links = list(set(pdf_links))[:20]

        # Propaga i link estratti dal PDF negli external_links per l'AI e gli IOC
        if pdf_links:
            for link in pdf_links:
                parsed = urlparse(link)
                if parsed.hostname and not link.startswith(origin):
                    external_links.append(link)

        if any([
            aitm.tokenized_redirect_chain,
            aitm.high_entropy_payload,
            aitm.microsoft_cdn_cloning,
            aitm.me_htm_patched,
            aitm.helper_subdomain,
            aitm.content_bridge,
        ]):
            logger.info(
                "AiTM signals detected for %s: tokenized=%s entropy=%s cdn=%s mehtm=%s helper=%s bridge=%s",
                url,
                aitm.tokenized_redirect_chain,
                aitm.high_entropy_payload,
                aitm.microsoft_cdn_cloning,
                aitm.me_htm_patched,
                aitm.helper_subdomain,
                aitm.content_bridge,
            )

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
            aitm_signals=aitm,
            suspicious_keywords=found_keywords,
            ocr_detected_text=ocr_text,
            load_time_ms=load_time_ms,
            ssl_info=ssl_info,
            screenshot_base64=screenshot_b64,
            error=error_msg,
        )


playwright_service = PlaywrightService()
