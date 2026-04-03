"""
Google Safe Browsing Agent — checks URLs against Google's Safe Browsing API.

Improvements:
- Structured logging instead of silent failures
- Configurable fail-open vs fail-closed behavior
- API key loaded from env (never logged/exposed)
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass
from typing import Any, Dict, List

import requests
from dotenv import load_dotenv

load_dotenv()  # Load .env once at import time

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SafeBrowsingResult:
    input_domain: str
    is_safe: bool
    threat_matches: List[Dict[str, Any]]
    risk_score: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_domain": self.input_domain,
            "is_safe": self.is_safe,
            "threat_matches": self.threat_matches,
            "risk_score": self.risk_score,
        }


class SafeBrowsingAgent:
    """
    Agent that uses Google Safe Browsing API to detect known malicious URLs.
    Expects GOOGLE_SAFE_BROWSING_API_KEY or API_KEY as env var.
    """

    ENDPOINT_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={}"

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
            return SafeBrowsingResult(
                input_domain=url,
                is_safe=True,
                threat_matches=[],
                risk_score=0.0,
            )

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
            response = session.post(endpoint, json=payload, timeout=self._timeout)
            response.raise_for_status()

            result = response.json()
            matches = result.get("matches", [])

            is_safe = len(matches) == 0
            risk_score = 0.0 if is_safe else 1.0

            if not is_safe:
                logger.warning("Safe Browsing flagged %s with %d threat(s)", url, len(matches))

            return SafeBrowsingResult(
                input_domain=url,
                is_safe=is_safe,
                threat_matches=matches,
                risk_score=risk_score,
            )

        except Exception as exc:
            logger.error("Safe Browsing API error for %s: %s", url, exc)
            # Fail open by default (assume safe if API is unreachable)
            if self._fail_open:
                return SafeBrowsingResult(
                    input_domain=url,
                    is_safe=True,
                    threat_matches=[],
                    risk_score=0.0,
                )
            else:
                # Fail closed — treat as suspicious
                return SafeBrowsingResult(
                    input_domain=url,
                    is_safe=False,
                    threat_matches=[],
                    risk_score=0.3,  # Moderate risk when can't verify
                )


    def _get_session(self) -> requests.Session:
        """Return a per-thread requests.Session — thread-safe by isolation."""
        if not hasattr(self._thread_local, "session"):
            self._thread_local.session = requests.Session()
        return self._thread_local.session


__all__ = ["SafeBrowsingAgent", "SafeBrowsingResult"]
