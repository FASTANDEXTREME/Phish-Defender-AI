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
from core.config import (
    KNOWN_BRANDS,
    SUSPICIOUS_CONTENT_KEYWORDS,
    PAYMENT_KEYWORDS,
    SCAM_KEYWORDS,
    INTENT_OTP,
    SUSPICIOUS_PATHS,
)

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

_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

_MODERN_HEADERS = {
    "User-Agent": _USER_AGENT,
    "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Upgrade-Insecure-Requests": "1",
    "Connection": "keep-alive",
    "Cache-Control": "max-age=0"
}


def _get_thread_session() -> requests.Session:
    """Return a per-thread requests.Session — thread-safe by isolation."""
    if not hasattr(_thread_local, "session"):
        session = requests.Session()
        session.headers.update(_MODERN_HEADERS)
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
            
            # FAST RENDER & SSRF SHIELD: Block unnecessary resources and private IPs
            def route_intercept(route):
                r_type = route.request.resource_type
                r_url = route.request.url.lower()
                
                # Fast, non-blocking string-based SSRF Check
                if any(p in r_url for p in ["127.0.0.1", "localhost", "192.168.", "10.0.0."]):
                    route.abort("blockedbyclient")
                    return

                if r_type in ["image", "media", "font", "other"]:
                    route.abort()
                else:
                    route.continue_()
            
            context.route("**/*", route_intercept)
            
            page = context.new_page()
            # Set a hard ceiling on ALL page operations (both default and navigation)
            page.set_default_timeout(timeout_ms)
            page.set_default_navigation_timeout(timeout_ms)
            
            # Track whether navigation succeeded — if it fails (timeout, stall,
            # adversarial response), we must NOT call page.evaluate() on the
            # undefined page state, as it can hang indefinitely.
            goto_succeeded = False
            try:
                # Use domcontentloaded instead of networkidle for much faster resolution
                page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                goto_succeeded = True
                
                # Very brief wait for high-risk elements
                try:
                    page.wait_for_selector('input[type="password"], input[name*="pass"], input[type="text"]', timeout=1000)
                except Exception:
                    pass
                
                # Quick DOM Stability Check
                try:
                    page.evaluate('''() => {
                        return new Promise(resolve => {
                            setTimeout(resolve, 800);
                        });
                    }''')
                except Exception:
                    pass
                    
            except Exception as e:
                logger.debug("Playwright goto/wait exception for %s: %s", url, e)

            # SAFEGUARD: Only extract DOM if goto succeeded. If the page never
            # loaded (adversarial stall, timeout, connection refused), calling
            # evaluate() on the empty/broken page can hang or return garbage.
            if not goto_succeeded:
                logger.debug("Skipping DOM extraction — page.goto() failed for %s", url)
                return None, None

            # Extract DOM content with its own safety net
            try:
                content = page.evaluate("""
                    () => {
                        function pierce(root) {
                            try {
                                root.querySelectorAll('*').forEach(el => {
                                    if (el.shadowRoot) {
                                        pierce(el.shadowRoot);
                                        el.innerHTML += el.shadowRoot.innerHTML;
                                    }
                                });
                            } catch (e) {}
                        }
                        pierce(document);
                        return document.documentElement.outerHTML;
                    }
                """)
            except Exception as exc:
                logger.debug("DOM extraction evaluate() failed for %s: %s", url, exc)
                return None, None

            final_url = page.url
            return content, final_url
        except Exception as exc:
            logger.debug("Browser pool fetch failed for %s: %s", url, exc)
            if "Browser has been closed" in str(exc) or "Target closed" in str(exc) or "Connection closed" in str(exc):
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
    # --- C1: Brand impersonation ---
    brand_impersonation_brands: List[str]
    # --- C6: Sensitive field detection ---
    payment_form_detected: bool
    scam_indicators_found: List[str]
    otp_detected: bool
    final_url: str
    final_domain: str
    is_provider_blocklisted: bool
    # --- C5: Playwright availability ---
    playwright_available: bool

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
            "brand_impersonation_brands": self.brand_impersonation_brands,
            "payment_form_detected": self.payment_form_detected,
            "scam_indicators_found": self.scam_indicators_found,
            "otp_detected": self.otp_detected,
            "final_url": self.final_url,
            "final_domain": self.final_domain,
            "is_provider_blocklisted": self.is_provider_blocklisted,
            "playwright_available": self.playwright_available,
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

        pw_available = _browser_pool.is_available
        if not pw_available:
            logger.warning(
                "⚠️ PLAYWRIGHT UNAVAILABLE — JS-rendered content will NOT be analyzed. "
                "Detection accuracy is severely degraded for JS-heavy sites (Weebly, Webflow, Vercel, etc.)."
            )

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
                brand_impersonation_brands=[],
                payment_form_detected=False,
                scam_indicators_found=[],
                otp_detected=False,
                final_url="",
                final_domain="",
                is_provider_blocklisted=False,
                playwright_available=pw_available,
            )

        page_domain = self._extract_domain(final_url or input_domain)

        soup = BeautifulSoup(html, "html.parser")

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
                # Fuzzy keyword matching for obfuscations like "pass**rd", bound to avoid ReDoS
                if re.search(r"p[a-z@*.,]{0,5}s[a-z*.,]{0,5}[w*.,]{0,5}r[a-z*.,]{0,5}d", combined):
                    has_pw = True
                if any(kw in combined for kw in ["email", "user", "otp", "code", "card", "anmeld"]):
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

        # --- Deep DOM & Accessibility Text Extraction ---
        hidden_text_signals = []
        for svg in soup.find_all("svg"):
            svg_title = svg.find("title")
            if svg_title: hidden_text_signals.append(svg_title.text)
        for tag in soup.find_all(attrs={"aria-label": True}):
            hidden_text_signals.append(tag["aria-label"])
        for meta_tag in soup.find_all("meta", property="og:site_name"):
            hidden_text_signals.append(meta_tag.get("content", ""))

        # --- Full visible text for multiple analyses ---
        text = soup.get_text(separator=" ").lower()
        if hidden_text_signals:
            text += " " + " ".join(hidden_text_signals).lower()

        # --- Suspicious keywords ---
        suspicious_found: List[str] = [
            keyword for keyword in SUSPICIOUS_CONTENT_KEYWORDS if keyword in text
        ]

        # =============================================================
        # C1: BRAND IMPERSONATION DETECTION
        # Scans page text, title, img alt/src for brand names.
        # If brand found on a non-brand domain → impersonation.
        # =============================================================
        brand_impersonation_brands = self._detect_brand_impersonation(soup, text, page_title, page_domain)
        if brand_impersonation_brands:
            logger.warning(
                "Brand impersonation detected on %s: page references brands %s",
                page_domain, brand_impersonation_brands,
            )

        # =============================================================
        # C6: PAYMENT / CREDIT CARD DETECTION
        # =============================================================
        payment_form_detected = self._detect_payment_fields(soup, text)

        # =============================================================
        # C6: TECH SUPPORT SCAM DETECTION
        # =============================================================
        scam_indicators_found: List[str] = [
            kw for kw in SCAM_KEYWORDS if kw in text
        ]
        
        # Scan for Toll-Free US numbers adjacent to support/scare text (I5)
        if re.search(r'(?i)(?:apple|microsoft|support|windows|virus).*?(?:1[-.\s]?)?8[0-9]{2}[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}', text) or \
           re.search(r'(?i)(?:1[-.\s]?)?8[0-9]{2}[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}.*?(?:apple|microsoft|support|windows|virus)', text):
            scam_indicators_found.append("toll-free phone number")

        # =============================================================
        # C6: OTP / VERIFICATION CODE DETECTION (Multilingual)
        # =============================================================
        try:
            from langdetect import detect
            page_lang = detect(text)
        except Exception:
            page_lang = "en"
        
        lang_otp_keywords = INTENT_OTP.get(page_lang, INTENT_OTP["en"]).copy()
        
        # Always check English keywords as fallback in case language detection fails or site is mixed
        if page_lang != "en":
            lang_otp_keywords.extend(INTENT_OTP["en"])
            
        # DEEPER INSIGHT: langdetect frequently fails or hallucinates on "Lonely Form" pages 
        # that have fewer than 20-50 words. To prevent evasion on minimalist checkpoints,
        # we check the unified vocabulary across all tracked languages.
        if len(text.split()) < 75:
            lang_otp_keywords = [kw for kws in INTENT_OTP.values() for kw in kws]
            
        otp_detected = any(kw in text for kw in set(lang_otp_keywords))

        # --- External scripts & JS Obfuscation ---
        scripts = soup.find_all("script")
        external_scripts_count = 0
        js_risk = 0.0
        for script in scripts:
            if script.string:
                script_text = script.string.lower()
                if "eval(function(p,a,c,k,e,d)" in script_text:
                    js_risk += 0.30
                if "atob(" in script_text and script_text.count("\\x") > 10:
                    js_risk += 0.20

            src = script.get("src", "").lower()
            if not src:
                continue
            if src.startswith("http://") or src.startswith("https://") or src.startswith("//"):
                external_scripts_count += 1
            if any(cdn in src for cdn in ["pastebin.com", "raw.githubusercontent.com", "worker.dev"]):
                js_risk += 0.25
        
        js_risk = min(0.40, js_risk)

        # --- Suspicious iframes ---
        iframes = soup.find_all("iframe")
        suspicious_iframes = sum(
            1 for iframe in iframes
            if iframe.get("src", "").startswith("http")
        )

        # --- Redirect detection ---
        # Look for meta refresh that redirects specifically
        has_meta_refresh = False
        meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)})
        if meta_refresh:
            content_attr = meta_refresh.get("content", "")
            if "url=" in str(content_attr).lower():
                has_meta_refresh = True

        raw_html = str(soup)
        has_js_redirect = bool(re.search(
            r"window\.location|document\.location|location\.href|location\.replace",
            raw_html,
        ))

        # =============================================================
        # BLOCK PAGE INTERCEPTION
        # Correctly identify mitigation pages that block phishing links
        # we treat a blocked link as confirmed malicious
        # =============================================================
        is_provider_blocklisted = False
        if ("tinyurl" in page_domain or "bit.ly" in page_domain or "qrco.de" in page_domain or "framer" in page_domain):
            if "blocked" in page_title.lower() or "blacklisted" in page_title.lower() or "phishing" in page_title.lower():
                is_provider_blocklisted = True
                scam_indicators_found.append("Provider Blocklisted")

        # =============================================================
        # I4: URL PATH ANALYSIS
        # =============================================================
        path = urlparse(final_url or input_domain).path.lower()
        path_risk = min(0.30, sum(0.15 for p in SUSPICIOUS_PATHS if re.search(p, path)))
        import math
        from collections import Counter
        def domain_entropy(s: str) -> float:
            if not s: return 0.0
            freq = Counter(s)
            return -sum((c/len(s)) * math.log2(c/len(s)) for c in freq.values())
            
        if path and len(path) > 10 and domain_entropy(path) > 4.0:
            path_risk += 0.20

        word_count = len(text.split())
        total_links = len(soup.find_all("a"))
        has_button = bool(soup.find("button") or soup.find("input", {"type": "submit"}))
        has_lonely_form = False
        if len(text_inputs) in [1, 2] and has_button and total_links < 3 and word_count < 100:
            has_lonely_form = True

        # Tightened: brand impersonation, payment forms, and scam indicators
        # now also prevent legitimate_app_behavior classification.
        is_legitimate_app = (
            not login_form_detected and
            not password_field_detected and
            not suspicious_found and
            not payment_form_detected and        # C6: payment fields block legitimate
            not scam_indicators_found and        # C6: scam indicators block legitimate
            not otp_detected and                 # C6: OTP fields block legitimate
            not is_provider_blocklisted and      # Block pages are NEVER legitimate apps
            cross_domain_forms == 0 and
            hidden_inputs_count < 3 and
            suspicious_iframes == 0 and
            not has_meta_refresh and
            not has_js_redirect and
            bool(page_title) and
            len(page_title) > 5                  # Trivial titles like "Page" are suspicious
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
            brand_impersonation_count=len(brand_impersonation_brands),
            payment_form_detected=payment_form_detected,
            scam_indicators_count=len(scam_indicators_found),
            otp_detected=otp_detected,
            path_risk=path_risk,
            is_provider_blocklisted=is_provider_blocklisted,
            has_lonely_form=has_lonely_form,
            js_risk=js_risk,
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
            brand_impersonation_brands=brand_impersonation_brands,
            payment_form_detected=payment_form_detected,
            scam_indicators_found=scam_indicators_found,
            otp_detected=otp_detected,
            final_url=final_url or input_domain,
            final_domain=page_domain,
            is_provider_blocklisted=is_provider_blocklisted,
            playwright_available=pw_available,
        )

    # ------------------------------------------------------------------
    # HTML fetching
    # ------------------------------------------------------------------

    def _fetch_html(self, target: str) -> tuple[Optional[str], Optional[str]]:
        """
        Try HTTPS first, then HTTP. Return (html, final_url) or (None, None).
        Uses browser pool for Playwright, per-thread session for HTTP fallback.
        Limits response to MAX_RESPONSE_SIZE bytes.
        
        FP-Fix: Increased redirect limit from 3→5, added secondary fallback
        with alternative User-Agent to reduce "Actually DEAD" failures.
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
                # Playwright failed — fall through to HTTP (don't return None yet)
                logger.debug("Playwright fetch failed for %s, trying HTTP fallback", url)

            # 2. Primary HTTP fallback (thread-safe per-thread session)
            result = self._try_http_fetch(url, _USER_AGENT)
            if result is not None:
                return result
            
            # 3. Secondary HTTP fallback with alternative User-Agent
            # Some sites block the Chrome UA but allow simpler crawlers
            alt_ua = "Mozilla/5.0 (compatible; PhishDefender/1.0; +https://github.com/phishdefender)"
            result = self._try_http_fetch(url, alt_ua)
            if result is not None:
                return result

        return None, None

    def _try_http_fetch(self, url: str, user_agent: str) -> tuple[Optional[str], Optional[str]] | None:
        """
        Single HTTP fetch attempt with manual redirect handling and SSRF protection.
        Returns (html, final_url) on success, or None on failure.
        """
        try:
            session = _get_thread_session()
            # Use full modern headers, but override the User-Agent specifically
            headers = _MODERN_HEADERS.copy()
            headers["User-Agent"] = user_agent
            current_url = url
            content = None
            final_url = None
            
            for _ in range(5):  # FP-Fix: Increased from 3 to 5 redirects
                import socket
                import ipaddress
                from urllib.parse import urlparse, urljoin
                
                parsed = urlparse(current_url)
                host = parsed.hostname
                if host:
                    try:
                        addr_info = socket.getaddrinfo(host, None)
                        is_private = False
                        for result in addr_info:
                            ip_str = result[4][0]
                            ip_obj = ipaddress.ip_address(ip_str)
                            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
                                is_private = True
                                break
                        if is_private:
                            break # SSRF blocked
                    except Exception:
                        pass # Let request attempt fail natively
                
                resp = session.get(
                    current_url,
                    timeout=self._timeout,
                    verify=False,
                    stream=True,
                    allow_redirects=False,
                    headers=headers,
                )
                
                # Redirect Handling
                if 300 <= resp.status_code < 400 and 'Location' in resp.headers:
                    current_url = urljoin(current_url, resp.headers['Location'])
                    continue
                    
                # Target content Reached
                if 200 <= resp.status_code < 400:
                    chunks: list[bytes] = []
                    downloaded = 0
                    for chunk in resp.iter_content(chunk_size=65_536):
                        chunks.append(chunk)
                        downloaded += len(chunk)
                        if downloaded >= MAX_RESPONSE_SIZE:
                            break
                    content_bytes = b"".join(chunks)[:MAX_RESPONSE_SIZE]
                    content = content_bytes.decode("utf-8", errors="replace")
                    final_url = current_url
                
                break # Stop redirect processing if not a 3xx

            if content is not None:
                return content, final_url
        except Exception:
            pass
        return None

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
    # C1: Brand impersonation detection (CONTEXT-AWARE REWRITE)
    # ------------------------------------------------------------------

    @staticmethod
    def _get_domain_brand_family(page_domain: str) -> set:
        """
        Given a page domain, return the set of brand names that are
        'owned' by that domain's organization (via BRAND_DOMAIN_ALIASES).
        
        e.g. page_domain='bing.com' → {'microsoft', 'outlook', 'skype', ...}
             page_domain='aws.amazon.com' → {'amazon', 'amazonaws', ...}
        """
        from core.config import BRAND_DOMAIN_ALIASES, KNOWN_BRANDS
        import tldextract
        
        ext = tldextract.extract(page_domain)
        page_root = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        
        # Collect all brand names whose canonical domain or alias matches page_domain
        family_brands: set = set()
        
        for canonical, aliases in BRAND_DOMAIN_ALIASES.items():
            canon_ext = tldextract.extract(canonical)
            canon_root = f"{canon_ext.domain}.{canon_ext.suffix}" if canon_ext.suffix else canon_ext.domain
            
            # Check if page is the canonical domain, or an alias, or a subdomain of either
            all_domains = [canon_root] + aliases
            is_family = False
            for dom in all_domains:
                dom_ext = tldextract.extract(dom)
                dom_root = f"{dom_ext.domain}.{dom_ext.suffix}" if dom_ext.suffix else dom_ext.domain
                # Match root domain or if page_domain ends with the alias
                if page_root == dom_root or page_domain == dom or page_domain.endswith(f".{dom}"):
                    is_family = True
                    break
            
            if is_family:
                # Add all brands whose canonical domain is in this family
                for brand, brand_canonical in KNOWN_BRANDS.items():
                    brand_canon_ext = tldextract.extract(brand_canonical)
                    brand_canon_root = f"{brand_canon_ext.domain}.{brand_canon_ext.suffix}" if brand_canon_ext.suffix else brand_canon_ext.domain
                    if brand_canon_root == canon_root:
                        family_brands.add(brand)
                # Also add brands whose canonical domain matches any alias
                for alias in aliases:
                    alias_ext = tldextract.extract(alias)
                    alias_root = f"{alias_ext.domain}.{alias_ext.suffix}" if alias_ext.suffix else alias_ext.domain
                    for brand, brand_canonical in KNOWN_BRANDS.items():
                        bc_ext = tldextract.extract(brand_canonical)
                        bc_root = f"{bc_ext.domain}.{bc_ext.suffix}" if bc_ext.suffix else bc_ext.domain
                        if bc_root == alias_root:
                            family_brands.add(brand)
        
        # Also, the page's own domain name might be a brand
        for brand, brand_canonical in KNOWN_BRANDS.items():
            bc_ext = tldextract.extract(brand_canonical)
            bc_root = f"{bc_ext.domain}.{bc_ext.suffix}" if bc_ext.suffix else bc_ext.domain
            if page_root == bc_root:
                family_brands.add(brand)
        
        return family_brands

    @staticmethod
    def _detect_brand_impersonation(
        soup: BeautifulSoup,
        visible_text: str,
        page_title: str,
        page_domain: str,
    ) -> List[str]:
        """
        Context-aware brand impersonation detection.
        
        Key improvements over previous implementation:
        1. Domain alias awareness — won't flag bing.com for mentioning "microsoft"
        2. Ambiguous brand filtering — common English words (chase, regions, meta)
           only flagged if they appear prominently in title/headings
        3. SSO brand filtering — social login mentions require high-signal context
        4. Parent-subsidiary awareness — apple.com mentioning "icloud" is NOT impersonation
        
        Returns list of impersonated brand names.
        """
        from core.config import SOCIAL_OR_SSO_BRANDS, AMBIGUOUS_BRAND_NAMES, BRAND_DOMAIN_ALIASES
        
        # --- Step 1: Compute brand family for this domain ---
        # All brands that are "owned" by this page's organization
        family_brands = WebsiteContentAgent._get_domain_brand_family(page_domain)
        
        # --- Step 2: Build high-signal vs low-signal text ---
        high_signal_text = f"{page_title.lower()}"
        for tag in soup.find_all(['h1', 'h2']):
            high_signal_text += f" {tag.get_text().lower()}"
            
        low_signal_text = visible_text
        for img in soup.find_all("img"):
            alt = img.get("alt", "")
            src = img.get("src", "").split("/")[-1].split("?")[0]
            low_signal_text += f" {alt.lower()} {src.lower()}"

        for meta in soup.find_all("meta"):
            prop = meta.get("property", "").lower()
            name_attr = meta.get("name", "").lower()
            if prop in ("og:title", "og:site_name"):
                high_signal_text += f" {meta.get('content', '').lower()}"
            elif prop == "og:description" or name_attr == "description":
                low_signal_text += f" {meta.get('content', '').lower()}"

        search_text = high_signal_text + " " + low_signal_text
        detected: List[str] = []

        for brand, canonical_domain in KNOWN_BRANDS.items():
            if len(brand) <= 2:
                continue

            # --- Step 3: Skip brands owned by this domain's organization ---
            if brand in family_brands:
                continue

            import tldextract
            ext = tldextract.extract(page_domain)
            canon_root = canonical_domain.split(".")[0]
            if canon_root == ext.domain:
                continue

            # --- Step 4: Ambiguous brand enforcement ---
            # Brands that are common English words MUST appear in high-signal
            # locations (title, h1, h2) to trigger. Body-text-only = IGNORED.
            if brand in AMBIGUOUS_BRAND_NAMES:
                if len(brand) == 3:
                    if not re.search(rf'(?:^|\s|[^a-z]){re.escape(brand)}(?:$|\s|[^a-z])', high_signal_text):
                        continue
                else:
                    if brand not in high_signal_text:
                        continue

            # --- Step 5: SSO/Social brand enforcement ---
            # Social login mentions require high-signal context
            elif brand in SOCIAL_OR_SSO_BRANDS:
                if len(brand) == 3:
                    if not re.search(rf'(?:^|\s|[^a-z]){re.escape(brand)}(?:$|\s|[^a-z])', high_signal_text):
                        continue
                else:
                    if brand not in high_signal_text:
                        continue

            # --- Step 6: Standard brand matching ---
            else:
                if len(brand) == 3:
                    if not re.search(rf'(?:^|\s|[^a-z]){re.escape(brand)}(?:$|\s|[^a-z])', search_text):
                        continue
                else:
                    if brand not in search_text:
                        continue
                    
                    # For non-ambiguous, non-SSO brands found only in body text
                    # (not in title/headings), require at least 2 mentions to
                    # reduce false positives from incidental editorial references
                    if brand not in high_signal_text:
                        mention_count = search_text.count(brand)
                        if mention_count < 2:
                            continue

            detected.append(brand)

        # Deduplicate brands that share a canonical domain
        return list(dict.fromkeys(detected))

    # ------------------------------------------------------------------
    # C6: Payment / sensitive field detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_payment_fields(soup: BeautifulSoup, visible_text: str) -> bool:
        """
        Detect payment/credit card collection beyond just input attributes.
        Checks:
        1. Input attributes (name, id, placeholder, autocomplete)
        2. Visible text for payment-related phrases
        3. Stripe/payment iframe patterns
        """
        # 1. Check input field attributes for payment-specific patterns
        payment_input_keywords = [
            "card", "cvv", "cvc", "ccnum", "cc-num", "cc_num",
            "cardnumber", "card-number", "card_number",
            "expir", "exp-date", "exp_date",
            "cardholder", "card-holder",
            "billing", "payment",
        ]
        for inp in soup.find_all("input"):
            attrs_text = " ".join([
                str(inp.get("name", "")),
                str(inp.get("id", "")),
                str(inp.get("placeholder", "")),
                str(inp.get("autocomplete", "")),
                str(inp.get("aria-label", "")),
                " ".join(inp.get("class", [])) if isinstance(inp.get("class"), list) else str(inp.get("class", "")),
            ]).lower()
            if any(kw in attrs_text for kw in payment_input_keywords):
                return True

        # 2. Check for Stripe / payment iframes
        for iframe in soup.find_all("iframe"):
            src = iframe.get("src", "").lower()
            if "stripe" in src or "braintree" in src or "checkout" in src or "payment" in src:
                return True

        # 3. Check visible text for payment keyword phrases
        matches = sum(1 for kw in PAYMENT_KEYWORDS if kw in visible_text)
        if matches >= 2:  # At least 2 payment phrases to avoid false positives
            return True

        return False

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
        brand_impersonation_count: int = 0,
        payment_form_detected: bool = False,
        scam_indicators_count: int = 0,
        otp_detected: bool = False,
        path_risk: float = 0.0,
        is_provider_blocklisted: bool = False,
        has_lonely_form: bool = False,
        js_risk: float = 0.0,
    ) -> float:
        risk = 0.0
        risk += path_risk
        risk += js_risk
        
        # Structural Minimalist Form Detection (Contextual Gateway)
        if has_lonely_form:
            risk += 0.40

        if is_legitimate_app:
            # Baseline risk reduction handled securely in DecisionAgent now
            risk += 0.0

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

        # =============================================================
        # C1: Brand impersonation — defense-in-depth signal
        # Primary scoring now handled by Cross-Reference Engine.
        # Content agent retains a reduced signal so detection still works
        # if CRE is unavailable (graceful degradation).
        # =============================================================
        if brand_impersonation_count >= 2:
            risk += 0.15  # Reduced from 0.70 — CRE handles the heavy scoring
        elif brand_impersonation_count == 1:
            risk += 0.10  # Reduced from 0.55 — CRE handles the heavy scoring

        # =============================================================
        # C6: Payment form detection — collecting financial data
        # =============================================================
        if payment_form_detected:
            risk += 0.45  # Payment collection on non-brand domain is high risk

        # =============================================================
        # C6: Tech support scam indicators
        # =============================================================
        if scam_indicators_count >= 3:
            risk += 0.60  # Strong scam signals
        elif scam_indicators_count >= 1:
            risk += 0.35  # Some scam signals

        # =============================================================
        # C6: OTP/verification code page
        # =============================================================
        if otp_detected:
            risk += 0.25

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

        if is_provider_blocklisted:
            risk = 1.0  # Bypass all other scoring

        if suspicious_iframes > 0:
            risk += 0.10

        if has_meta_refresh or has_js_redirect:
            risk += 0.05

        return max(0.0, min(1.0, risk))


__all__ = ["WebsiteContentAgent", "WebsiteContentResult"]
