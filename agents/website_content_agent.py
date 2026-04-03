"""
Website Content Analysis Agent — downloads HTML content, parses it, and
extracts phishing-related signals from the DOM structure.

Improvements over MVP:
- Cross-domain form action detection (credential harvesting)
- Hidden input analysis (session hijacking patterns)
- Suspicious iframe detection
- Meta-refresh and JavaScript redirect detection
- Expanded keyword set from centralized config
- Response size limiting (2MB) for performance
- Persistent browser pool for Playwright (reuse instead of launch-per-request)
- Thread-safe HTTP via per-thread requests.Session
"""

from __future__ import annotations

import atexit
import logging
import re
import threading
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from agents.decision_agent import WebsiteContentAgentOutput
from core.config import SUSPICIOUS_CONTENT_KEYWORDS

# Suppress InsecureRequestWarning once at module level
import warnings
from urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Maximum HTML to download (bytes). Increased to 2MB to accommodate heavy JS/React phishing pages.
MAX_RESPONSE_SIZE = 2_000_000

# ---------------------------------------------------------------------------
# Thread-safe requests.Session pool via threading.local
# Each thread gets its own Session — no shared state, no race conditions.
# ---------------------------------------------------------------------------
_thread_local = threading.local()

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


def _get_thread_session() -> requests.Session:
    """Return a per-thread requests.Session — thread-safe by isolation."""
    if not hasattr(_thread_local, "session"):
        session = requests.Session()
        session.headers.update({"User-Agent": _USER_AGENT})
        _thread_local.session = session
    return _thread_local.session


# ---------------------------------------------------------------------------
# Persistent Playwright browser pool
# Keeps ONE browser alive across requests — creates new contexts per request.
# Contexts are isolated (separate cookies/storage) but share the same process.
# ---------------------------------------------------------------------------
class _BrowserPool:
    """
    Manages a persistent Chromium browser instance for Playwright.
    
    - One browser process shared across all requests (saves ~200MB RAM per request)
    - Each request gets a fresh BrowserContext (isolated cookies/storage)
    - Thread-safe via a lock
    - Auto-cleanup on process exit via atexit
    """

    def __init__(self):
        self._browser = None
        self._playwright = None
        self._lock = threading.Lock()
        self._available = False
        self._checked = False

    def _ensure_browser(self) -> bool:
        """Lazily start the persistent browser. Returns True if available."""
        if self._checked and not self._available:
            return False

        with self._lock:
            if self._browser is not None:
                return True
            if self._checked:
                return self._available

            self._checked = True
            try:
                from playwright.sync_api import sync_playwright
                self._playwright = sync_playwright().start()
                self._browser = self._playwright.chromium.launch(
                    headless=True,
                    args=[
                        "--disable-blink-features=AutomationControlled",
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                    ],
                )
                self._available = True
                logger.info("Browser pool: Chromium launched — JS-rendered page analysis enabled")
                atexit.register(self.shutdown)
                return True
            except Exception as exc:
                self._available = False
                logger.warning(
                    "Browser pool: Playwright unavailable (%s). "
                    "Content agent will use raw HTTP fallback. "
                    "To enable: pip install playwright && playwright install chromium && playwright install-deps",
                    exc,
                )
                return False

    @property
    def is_available(self) -> bool:
        return self._ensure_browser()

    def fetch_page(self, url: str, timeout_ms: int) -> tuple[Optional[str], Optional[str]]:
        """
        Fetch a page using the pooled browser. Returns (html, final_url).
        Creates a fresh context per request for isolation.
        """
        if not self._ensure_browser():
            return None, None

        context = None
        try:
            context = self._browser.new_context(
                ignore_https_errors=True,
                user_agent=_USER_AGENT,
                viewport={"width": 1920, "height": 1080},
                locale="en-US",
            )
            page = context.new_page()
            # Set a hard ceiling on ALL page operations to prevent hung renderers
            page.set_default_timeout(timeout_ms + 5000)
            try:
                page.goto(url, timeout=timeout_ms, wait_until="networkidle")
            except Exception:
                pass  # Fallback — page may have partially loaded
            content = page.content()
            final_url = page.url
            return content, final_url
        except Exception as exc:
            logger.debug("Browser pool fetch failed for %s: %s", url, exc)
            # If the browser process crashed, mark as unavailable
            if "Browser has been closed" in str(exc) or "Target closed" in str(exc):
                with self._lock:
                    self._browser = None
                    self._checked = False
            return None, None
        finally:
            if context:
                try:
                    context.close()
                except Exception:
                    pass

    def shutdown(self):
        """Gracefully close the browser and Playwright server."""
        with self._lock:
            if self._browser:
                try:
                    self._browser.close()
                except Exception:
                    pass
                self._browser = None
            if self._playwright:
                try:
                    self._playwright.stop()
                except Exception:
                    pass
                self._playwright = None
            self._available = False


# Module-level singleton — shared across all WebsiteContentAgent instances
_browser_pool = _BrowserPool()


@dataclass(frozen=True)
class WebsiteContentResult:
    input_domain: str
    page_reachable: bool
    login_form_detected: bool
    password_field_detected: bool
    suspicious_keywords_found: List[str]
    external_scripts_count: int
    forms_count: int
    cross_domain_forms: int
    hidden_inputs_count: int
    suspicious_iframes: int
    has_meta_refresh: bool
    has_js_redirect: bool
    page_title: Optional[str]
    legitimate_app_behavior: bool
    risk_score: float

    def to_dict(self) -> WebsiteContentAgentOutput:
        return {
            "input_domain": self.input_domain,
            "page_reachable": self.page_reachable,
            "login_form_detected": self.login_form_detected,
            "password_field_detected": self.password_field_detected,
            "suspicious_keywords_found": self.suspicious_keywords_found,
            "external_scripts_count": self.external_scripts_count,
            "forms_count": self.forms_count,
            "cross_domain_forms": self.cross_domain_forms,
            "hidden_inputs_count": self.hidden_inputs_count,
            "suspicious_iframes": self.suspicious_iframes,
            "has_meta_refresh": self.has_meta_refresh,
            "has_js_redirect": self.has_js_redirect,
            "page_title": self.page_title,
            "legitimate_app_behavior": self.legitimate_app_behavior,
            "risk_score": self.risk_score,
        }


class WebsiteContentAgent:
    """
    Website Content Analysis Agent.
    Downloads HTML content, parses it, and extracts phishing-related signals.
    Uses a persistent browser pool for Playwright and per-thread HTTP sessions.
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout

    def run(self, domain: str) -> WebsiteContentResult:
        input_domain = domain.strip().lower()

        html, final_url = self._fetch_html(input_domain)
        if html is None:
            return WebsiteContentResult(
                input_domain=input_domain,
                page_reachable=False,
                login_form_detected=False,
                password_field_detected=False,
                suspicious_keywords_found=[],
                external_scripts_count=0,
                forms_count=0,
                cross_domain_forms=0,
                hidden_inputs_count=0,
                suspicious_iframes=0,
                has_meta_refresh=False,
                has_js_redirect=False,
                page_title=None,
                legitimate_app_behavior=False,
                risk_score=0.0,
            )

        page_domain = self._extract_domain(final_url or input_domain)

        soup = BeautifulSoup(html, "lxml")

        # --- Forms & Inputs ---
        forms = soup.find_all("form")
        forms_count = len(forms)

        password_inputs = soup.find_all("input", {"type": "password"})
        password_field_detected = len(password_inputs) > 0

        # Enhance detection for Modern phishing: they often use generic 'text' or 'email' inputs for credentials/OTP/Cards
        text_inputs = soup.find_all("input", {"type": ["text", "email", "tel", "number", ""]})
        suspicious_input_detected = False
        for inp in text_inputs:
            name = str(inp.get("name", "")).lower()
            id_ = str(inp.get("id", "")).lower()
            placeholder = str(inp.get("placeholder", "")).lower()
            combined_attrs = f"{name} {id_} {placeholder}"
            
            # Look for username, email, card, or OTP fields
            target_keywords = ["email", "user", "login", "password", "otp", "card", "cvv", "phone", "account"]
            if any(kw in combined_attrs for kw in target_keywords):
                suspicious_input_detected = True
                break

        login_form_detected = False
        for form in forms:
            has_pw = form.find("input", {"type": "password"}) is not None
            has_suspicious_txt = False
            for inp in form.find_all("input", {"type": ["text", "email", "tel", ""]}) + form.find_all("input", class_=True):
                combined = f"{inp.get('name','')} {inp.get('id','')} {inp.get('placeholder','')} {inp.get('class','')} ".lower()
                if any(kw in combined for kw in ["email", "user", "otp", "code", "card"]):
                    has_suspicious_txt = True
                    break
            
            if has_pw or has_suspicious_txt:
                login_form_detected = True
                break

        # Fallback if no <form> wrapper exists (React/Vue often just use raw divs and inputs with onClick handlers)
        if not login_form_detected and (password_field_detected or suspicious_input_detected):
            login_form_detected = True

        # Extract Title
        title_tag = soup.find("title")
        page_title = title_tag.text.strip() if title_tag else ""

        # --- Cross-domain form actions ---
        cross_domain_forms = self._count_cross_domain_forms(forms, page_domain)

        # --- Hidden inputs ---
        hidden_inputs = soup.find_all("input", {"type": "hidden"})
        hidden_inputs_count = len(hidden_inputs)

        # --- Suspicious keywords ---
        text = soup.get_text(separator=" ").lower()
        suspicious_found: List[str] = [
            keyword for keyword in SUSPICIOUS_CONTENT_KEYWORDS if keyword in text
        ]

        # --- External scripts ---
        scripts = soup.find_all("script")
        external_scripts_count = 0
        for script in scripts:
            src = script.get("src")
            if not src:
                continue
            if src.startswith("http://") or src.startswith("https://") or src.startswith("//"):
                external_scripts_count += 1

        # --- Suspicious iframes ---
        iframes = soup.find_all("iframe")
        suspicious_iframes = sum(
            1 for iframe in iframes
            if iframe.get("src", "").startswith("http")
        )

        # --- Redirect detection ---
        has_meta_refresh = bool(soup.find("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)}))
        raw_html = str(soup)
        has_js_redirect = bool(re.search(
            r"window\.location|document\.location|location\.href|location\.replace",
            raw_html,
        ))

        is_legitimate_app = (
            not login_form_detected and
            not password_field_detected and
            not suspicious_found and
            cross_domain_forms == 0 and
            hidden_inputs_count < 3 and
            suspicious_iframes == 0 and
            not has_meta_refresh and
            not has_js_redirect and
            bool(page_title)
        )

        risk_score = self._compute_risk_score(
            login_form_detected=login_form_detected,
            password_field_detected=password_field_detected,
            suspicious_keywords_found=suspicious_found,
            external_scripts_count=external_scripts_count,
            forms_count=forms_count,
            cross_domain_forms=cross_domain_forms,
            hidden_inputs_count=hidden_inputs_count,
            suspicious_iframes=suspicious_iframes,
            has_meta_refresh=has_meta_refresh,
            has_js_redirect=has_js_redirect,
            page_title=page_title,
            is_legitimate_app=is_legitimate_app,
        )

        return WebsiteContentResult(
            input_domain=input_domain,
            page_reachable=True,
            login_form_detected=login_form_detected,
            password_field_detected=password_field_detected,
            suspicious_keywords_found=suspicious_found,
            external_scripts_count=external_scripts_count,
            forms_count=forms_count,
            cross_domain_forms=cross_domain_forms,
            hidden_inputs_count=hidden_inputs_count,
            suspicious_iframes=suspicious_iframes,
            has_meta_refresh=has_meta_refresh,
            has_js_redirect=has_js_redirect,
            page_title=page_title,
            legitimate_app_behavior=is_legitimate_app,
            risk_score=risk_score,
        )

    # ------------------------------------------------------------------
    # HTML fetching
    # ------------------------------------------------------------------

    def _fetch_html(self, target: str) -> tuple[Optional[str], Optional[str]]:
        """
        Try HTTPS first, then HTTP. Return (html, final_url) or (None, None).
        Uses browser pool for Playwright, per-thread session for HTTP fallback.
        Limits response to MAX_RESPONSE_SIZE bytes.
        """
        if target.startswith("http://") or target.startswith("https://"):
            urls = [target]
        else:
            urls = [f"https://{target}", f"http://{target}"]

        for url in urls:
            # 1. Try Playwright browser pool first (JS-rendered DOM)
            if _browser_pool.is_available:
                content, final_url = _browser_pool.fetch_page(
                    url, timeout_ms=int(self._timeout * 1000)
                )
                if content is not None:
                    if len(content) > MAX_RESPONSE_SIZE:
                        content = content[:MAX_RESPONSE_SIZE]
                    return content, final_url

            # 2. Fallback to raw HTTP (thread-safe per-thread session)
            try:
                session = _get_thread_session()
                resp = session.get(
                    url,
                    timeout=self._timeout,
                    verify=False,
                    stream=True,
                )
                if 200 <= resp.status_code < 400:
                    # Read incrementally up to MAX_RESPONSE_SIZE
                    chunks: list[bytes] = []
                    downloaded = 0
                    for chunk in resp.iter_content(chunk_size=65_536):
                        chunks.append(chunk)
                        downloaded += len(chunk)
                        if downloaded >= MAX_RESPONSE_SIZE:
                            break
                    content = b"".join(chunks)[:MAX_RESPONSE_SIZE]
                    return content.decode("utf-8", errors="replace"), resp.url
            except Exception:
                continue
        return None, None

    # ------------------------------------------------------------------
    # Analysis helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_domain(url: str) -> str:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return (parsed.hostname or "").lower()

    def _count_cross_domain_forms(self, forms, page_domain: str) -> int:
        """Count forms that submit to a different domain (credential harvesting)."""
        count = 0
        for form in forms:
            action = form.get("action", "")
            if not action or action.startswith("#") or action.startswith("/"):
                continue
            try:
                action_domain = self._extract_domain(action)
                if action_domain and action_domain != page_domain:
                    count += 1
            except Exception:
                continue
        return count

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def _compute_risk_score(
        self,
        login_form_detected: bool,
        password_field_detected: bool,
        suspicious_keywords_found: List[str],
        external_scripts_count: int,
        forms_count: int,
        cross_domain_forms: int,
        hidden_inputs_count: int,
        suspicious_iframes: int,
        has_meta_refresh: bool,
        has_js_redirect: bool,
        page_title: str,
        is_legitimate_app: bool,
    ) -> float:
        risk = 0.0

        if is_legitimate_app:
            # Baseline risk reduction for normal pages
            risk -= 0.20

        # Login form and password field — merged to avoid double-counting.
        # login_form_detected implies password_field_detected, so treat as one signal.
        if login_form_detected:
            risk += 0.40  # Unified login form signal (bumped up severity for form pages)
        elif password_field_detected:
            risk += 0.20  # Bare password field without form context

        # Title Impersonation (e.g. title is 'H-E-B Rewards Program' but domain is vercel)
        # We can safely flag certain keywords in titles
        if page_title:
            lower_title = page_title.lower()
            if any(kw in lower_title for kw in ["secure", "login", "auth", "verify", "account", "webmail", "reward"]):
                risk += 0.20

        # Cross-domain form submissions — strongest credential-harvesting indicator
        if cross_domain_forms > 0:
            risk += 0.35

        if suspicious_keywords_found:
            keyword_risk = min(len(suspicious_keywords_found) * 0.03, 0.15)
            risk += keyword_risk

        if external_scripts_count > 5:
            risk += 0.05

        if forms_count > 1:
            risk += 0.05

        if hidden_inputs_count > 3:
            risk += 0.05

        if suspicious_iframes > 0:
            risk += 0.10

        if has_meta_refresh or has_js_redirect:
            risk += 0.05

        return max(-0.20, min(1.0, risk))


__all__ = ["WebsiteContentAgent", "WebsiteContentResult"]
