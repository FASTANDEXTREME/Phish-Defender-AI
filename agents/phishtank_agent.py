"""
PhishTank Agent — Checks URLs against the PhishTank database.

Downloads the online-valid.json.gz from PhishTank if missing or older than 1 hour.
Refreshes are handled in a background thread to prevent latency spikes during
user requests (lazy refresh). Memory cache is an O(1) set.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Set
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.json.gz"
UPDATE_INTERVAL = 3600  # 1 hour

# Absolute path anchored to project root — works regardless of CWD
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATA_DIR = os.path.join(_PROJECT_ROOT, "data")
CACHE_FILE = os.path.join(_DATA_DIR, "phishtank.json.gz")


@dataclass(frozen=True)
class PhishTankResult:
    input_domain: str
    is_phishing: bool
    risk_score: float
    is_disabled: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_domain": self.input_domain,
            "is_phishing": self.is_phishing,
            "risk_score": self.risk_score,
            "is_disabled": self.is_disabled,
        }


class PhishTankAgent:
    """
    Agent that uses the PhishTank downloadable dataset to detect known phishing URLs.
    Caching ensures O(1) lookup latency.
    """

    def __init__(self):
        self._phish_set: Set[str] = set()
        self._lock = threading.Lock()
        self._refreshing = False

        # Ensure data directory exists
        os.makedirs(_DATA_DIR, exist_ok=True)

        # Attempt to load immediately from disk if available
        if os.path.exists(CACHE_FILE):
            self._load_from_disk()
        else:
            # Pre-seed in background at startup so the first user request isn't blocked
            logger.info("PhishTank cache not found — starting background download at startup")
            self._refreshing = True
            threading.Thread(target=self._download_and_cache, daemon=True).start()

    def _normalize_url(self, url: str) -> str:
        # Hack to ensure urlparse works if there is no scheme
        if not url.startswith("http"):
            url = f"http://{url}"
        parsed = urlparse(url)
        
        # PhishTank dataset has a mix of http and https. 
        # The safest approach is to store and match only the raw netloc + path.
        return f"{parsed.netloc}{parsed.path}".rstrip("/")

    def _load_from_disk(self):
        """Load the set from the local gzip file into memory."""
        try:
            with gzip.open(CACHE_FILE, "rt", encoding="utf-8") as f:
                data = json.load(f)
            
            new_set = set()
            for entry in data:
                url = entry.get("url")
                if url:
                    new_set.add(self._normalize_url(url))

            with self._lock:
                self._phish_set = new_set
            
            logger.info("Loaded %d phishing URLs from PhishTank disk cache", len(self._phish_set))
        except Exception as e:
            logger.error("Failed to load PhishTank from disk: %s", e)

    def _download_and_cache(self):
        """Download the latest file, save it to disk, and load it into memory."""
        logger.info("Downloading latest PhishTank data...")
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            resp = requests.get(PHISHTANK_URL, headers=headers, timeout=15)
            resp.raise_for_status()

            # Save explicitly to disk
            with open(CACHE_FILE, "wb") as f:
                f.write(resp.content)
            
            # Reload memory set
            self._load_from_disk()
            logger.info("PhishTank background update complete.")
            
        except Exception as e:
            logger.error("Failed to update PhishTank from network: %s", e)
        finally:
            self._refreshing = False

    def _check_refresh(self):
        """Non-blocking check if a refresh is needed based on file modification time."""
        if self._refreshing:
            return  # Already refreshing
            
        now = time.time()
        needs_refresh = False

        if not os.path.exists(CACHE_FILE):
            needs_refresh = True
        else:
            mtime = os.path.getmtime(CACHE_FILE)
            if now - mtime > UPDATE_INTERVAL:
                needs_refresh = True

        if needs_refresh:
            self._refreshing = True
            # Always refresh in background — never block user requests
            threading.Thread(target=self._download_and_cache, daemon=True).start()

    def run(self, url: str) -> PhishTankResult:
        full_url = url if url.startswith("http") else f"http://{url}"
        
        self._check_refresh()

        normalized = self._normalize_url(full_url)
        is_phishing = normalized in self._phish_set
        
        return PhishTankResult(
            input_domain=url,
            is_phishing=is_phishing,
            # Assigning 0.8 as requested (High Risk, but not explicitly 1.0 Phishing out of the box)
            risk_score=0.8 if is_phishing else 0.0,
            is_disabled=False
        )

__all__ = ["PhishTankAgent", "PhishTankResult"]
