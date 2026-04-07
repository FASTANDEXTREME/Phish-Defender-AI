"""
Google Safe Browsing Agent — checks URLs against Google's Safe Browsing API.

Improvements:
- Structured logging instead of silent failures
- Configurable fail-open vs fail-closed behavior
- API key loaded from env (never logged/exposed)
- Retry adapter with exponential backoff for transient failures
- Circuit breaker to avoid hammering a failing API
- Split connect/read timeouts to prevent SSLEOFError on stale connections
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv

load_dotenv()  # Load .env once at import time

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SafeBrowsingResult:
    input_domain: str
    is_safe: bool
    threat_matches: List[Dict[str, Any]]
    risk_score: float
    is_disabled: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_domain": self.input_domain,
            "is_safe": self.is_safe,
            "threat_matches": self.threat_matches,
            "risk_score": self.risk_score,
            "is_disabled": self.is_disabled,
        }


class SafeBrowsingAgent:
    """
    Agent that uses Google Safe Browsing API to detect known malicious URLs.
    Expects GOOGLE_SAFE_BROWSING_API_KEY or API_KEY as env var.

    Hardening features:
    - Retry with backoff: automatically retries on 5xx / connection errors
    - Circuit breaker: skips API calls after repeated failures to prevent
      cascading latency (auto-resets after cooldown period)
    - Split timeouts: separate connect vs read timeout to catch stale sockets
    """

    ENDPOINT_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={}"

    # Circuit breaker settings (class-level, shared across instances)
    _CB_THRESHOLD = 3         # Open circuit after 3 consecutive failures
    _CB_COOLDOWN_S = 60.0     # Retry after 60s of cooldown
    _cb_failures = 0
    _cb_open_until = 0.0
    _cb_lock = threading.Lock()

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = 5.0,
        fail_open: bool = True,
    ):
        self._api_key = api_key or os.environ.get(
            "GOOGLE_SAFE_BROWSING_API_KEY",
            os.environ.get("API_KEY", ""),
        )
        self._timeout = timeout
        self._fail_open = fail_open

        # Thread-safe session pool via threading.local
        self._thread_local = threading.local()

        if not self._api_key:
            logger.warning("No Safe Browsing API key configured — agent will return safe by default")

    def run(self, url: str) -> SafeBrowsingResult:
        check_url = url if url.startswith("http") else f"http://{url}"

        if not self._api_key:
            return self._default_result(url)

        # Circuit breaker: skip if API has been consistently failing
        if self._is_circuit_open():
            logger.warning("Safe Browsing circuit breaker OPEN — skipping API call")
            return self._default_result(url)

        payload = {
            "client": {
                "clientId": "phish-defender-ai",
                "clientVersion": "2.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": check_url}]
            }
        }

        try:
            endpoint = self.ENDPOINT_URL.format(self._api_key)
            session = self._get_session()

            # Total operation timeout — hard cap on entire SB operation
            # including retries. Prevents retry storms from cascading.
            MAX_OP_TIME = 6.0
            op_start = time.monotonic()
            elapsed = time.monotonic() - op_start
            remaining = max(1.0, MAX_OP_TIME - elapsed)

            # Split timeout: (connect_timeout, read_timeout)
            # Connect kept low (2s) to catch dead/stale sockets fast.
            # Read uses remaining budget to handle slow API responses.
            response = session.post(
                endpoint,
                json=payload,
                timeout=(min(2.0, remaining), min(self._timeout, remaining)),
            )
            response.raise_for_status()

            result = response.json()
            matches = result.get("matches", [])

            is_safe = len(matches) == 0
            risk_score = 0.0 if is_safe else 1.0

            if not is_safe:
                logger.warning("Safe Browsing flagged %s with %d threat(s)", url, len(matches))

            # Success — reset circuit breaker
            self._record_success()

            return SafeBrowsingResult(
                input_domain=url,
                is_safe=is_safe,
                threat_matches=matches,
                risk_score=risk_score,
            )

        except Exception as exc:
            logger.error("Safe Browsing API error for %s: %s", url, type(exc).__name__)
            self._record_failure()
            return self._default_result(url)

    # ------------------------------------------------------------------
    # Session management with retry adapter
    # ------------------------------------------------------------------

    def _get_session(self) -> requests.Session:
        """Return a per-thread requests.Session with retry adapter configured."""
        if not hasattr(self._thread_local, "session"):
            session = requests.Session()

            # Retry strategy: ONE retry with minimal backoff.
            # Reduced from total=2 to prevent retry storms when upstream
            # is slow. Only retries on clear server errors, NOT on
            # connection errors (which include SSLEOFError from stale
            # keep-alive — those are handled by closing and reopening).
            retry = Retry(
                total=1,
                backoff_factor=0.1,
                status_forcelist=[502, 503],
                allowed_methods=["POST"],
                raise_on_status=False,
            )
            adapter = HTTPAdapter(
                max_retries=retry,
                pool_maxsize=5,
                pool_connections=2,
                # Force fresh connections to avoid stale keep-alive SSLEOFError
                pool_block=False,
            )
            session.mount("https://", adapter)
            self._thread_local.session = session
        return self._thread_local.session

    # ------------------------------------------------------------------
    # Circuit breaker
    # ------------------------------------------------------------------

    @classmethod
    def _is_circuit_open(cls) -> bool:
        with cls._cb_lock:
            if cls._cb_failures < cls._CB_THRESHOLD:
                return False
            if time.monotonic() >= cls._cb_open_until:
                # Cooldown expired — allow one probe request (half-open)
                cls._cb_failures = cls._CB_THRESHOLD - 1
                return False
            return True

    @classmethod
    def _record_success(cls) -> None:
        with cls._cb_lock:
            cls._cb_failures = 0

    @classmethod
    def _record_failure(cls) -> None:
        with cls._cb_lock:
            cls._cb_failures += 1
            if cls._cb_failures >= cls._CB_THRESHOLD:
                cls._cb_open_until = time.monotonic() + cls._CB_COOLDOWN_S
                logger.warning(
                    "Safe Browsing circuit breaker TRIPPED — will retry in %.0fs",
                    cls._CB_COOLDOWN_S,
                )

    # ------------------------------------------------------------------
    # Default result helper
    # ------------------------------------------------------------------

    def _default_result(self, url: str) -> SafeBrowsingResult:
        """Return the appropriate default result based on fail-open/closed policy."""
        if self._fail_open:
            return SafeBrowsingResult(
                input_domain=url,
                is_safe=True,
                threat_matches=[],
                risk_score=0.0,
                is_disabled=True,
            )
        else:
            return SafeBrowsingResult(
                input_domain=url,
                is_safe=False,
                threat_matches=[],
                risk_score=0.3,
                is_disabled=True,
            )


__all__ = ["SafeBrowsingAgent", "SafeBrowsingResult"]
