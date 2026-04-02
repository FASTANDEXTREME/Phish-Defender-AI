"""
Domain Intelligence Agent — extracts WHOIS + DNS signals and computes a
risk score using graduated (non-binary) scoring.

Improvements over MVP:
- Graduated domain age risk (7 / 30 / 90 / 365-day tiers)
- WHOIS privacy only high-risk when combined with new domain
- Domain expiry proximity detection (min-registration phishing pattern)
- DNSSEC presence check (reduces risk for legitimate domains)
- Multiplicative scoring to avoid inflated scores from weak signals
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import dns.resolver
import whois
import tldextract

from agents.decision_agent import DomainIntelligenceAgentOutput
from core.config import KNOWN_HOSTING_PLATFORMS

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DomainIntelligenceResult:
    input_domain: str
    domain_age_days: Optional[int]
    is_new_domain: bool
    is_hosted_platform: bool
    whois_privacy_enabled: bool
    has_mx_record: bool
    nameserver_count: Optional[int]
    has_dnssec: bool
    short_expiry: bool
    risk_score: float

    def to_dict(self) -> DomainIntelligenceAgentOutput:
        return {
            "domain_age_days": self.domain_age_days,
            "is_new_domain": self.is_new_domain,
            "is_hosted_platform": self.is_hosted_platform,
            "whois_privacy_enabled": self.whois_privacy_enabled,
            "has_mx_record": self.has_mx_record,
            "nameserver_count": self.nameserver_count,
            "has_dnssec": self.has_dnssec,
            "short_expiry": self.short_expiry,
            "risk_score": self.risk_score,
        }


class DomainIntelligenceAgent:
    """
    Domain Intelligence Agent for the Intelligent Phishing Domain Detection system.
    """

    NEW_DOMAIN_THRESHOLD_DAYS: int = 30

    def __init__(
        self,
        whois_timeout: float = 5.0,
        dns_timeout: float = 3.0,
    ) -> None:
        self._whois_timeout = whois_timeout
        self._dns_timeout = dns_timeout

        # Reuse one resolver instance per agent (performance)
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = dns_timeout
        self._resolver.timeout = dns_timeout

    def run(self, domain: str) -> DomainIntelligenceResult:
        safe_domain = domain.strip().lower()
        
        # Clean the input to get just the hostname, as WHOIS fails on full URLs.
        if "://" not in safe_domain and "/" in safe_domain:
            parsed = urlparse("http://" + safe_domain)
        else:
            parsed = urlparse(safe_domain)
            
        safe_domain = parsed.hostname or safe_domain

        # For WHOIS, we must query the root domain, not the deep subdomain.
        ext = tldextract.extract(safe_domain)
        root_domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else safe_domain
        
        # Check if the root domain is a known hosting platform
        is_hosted_platform = root_domain in KNOWN_HOSTING_PLATFORMS

        whois_data = self._safe_fetch_whois(root_domain)
        domain_age_days = self._compute_domain_age_days(whois_data)
        is_new_domain = (
            domain_age_days is not None
            and domain_age_days < self.NEW_DOMAIN_THRESHOLD_DAYS
        )

        whois_privacy_enabled = self._detect_whois_privacy(whois_data)
        short_expiry = self._detect_short_expiry(whois_data)

        has_mx_record, nameserver_count = self._query_dns(safe_domain)
        has_dnssec = self._check_dnssec(safe_domain)

        risk_score = self._compute_risk_score(
            domain_age_days=domain_age_days,
            is_new_domain=is_new_domain,
            is_hosted_platform=is_hosted_platform,
            whois_privacy_enabled=whois_privacy_enabled,
            has_mx_record=has_mx_record,
            nameserver_count=nameserver_count,
            has_dnssec=has_dnssec,
            short_expiry=short_expiry,
        )

        return DomainIntelligenceResult(
            input_domain=safe_domain,
            domain_age_days=domain_age_days,
            is_new_domain=is_new_domain,
            is_hosted_platform=is_hosted_platform,
            whois_privacy_enabled=whois_privacy_enabled,
            has_mx_record=has_mx_record,
            nameserver_count=nameserver_count,
            has_dnssec=has_dnssec,
            short_expiry=short_expiry,
            risk_score=risk_score,
        )

    # --------------------
    # WHOIS helpers
    # --------------------

    def _safe_fetch_whois(self, domain: str) -> Dict[str, Any]:
        try:
            data = whois.whois(domain)
            if isinstance(data, dict):
                return data
            return dict(data)  # type: ignore[arg-type]
        except Exception:
            logger.debug("WHOIS lookup failed for %s", domain)
            return {}

    def _compute_domain_age_days(self, whois_data: Dict[str, Any]) -> Optional[int]:
        created = whois_data.get("creation_date") or whois_data.get("created")
        if created is None:
            return None

        if isinstance(created, list):
            created = min(created)

        if not isinstance(created, datetime):
            return None

        now = datetime.now(timezone.utc)
        created_utc = created
        if created_utc.tzinfo is None:
            created_utc = created_utc.replace(tzinfo=timezone.utc)

        return max((now - created_utc).days, 0)

    def _detect_whois_privacy(self, whois_data: Dict[str, Any]) -> bool:
        privacy_indicators = (
            "privacy",
            "protect",
            "redacted",
            "whoisguard",
            "contact privacy",
            "data protected",
            "withheld for privacy",
        )

        text_chunks: list[str] = []
        for value in whois_data.values():
            if isinstance(value, str):
                text_chunks.append(value.lower())
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        text_chunks.append(item.lower())

        combined = " ".join(text_chunks)
        return any(indicator in combined for indicator in privacy_indicators)

    def _detect_short_expiry(self, whois_data: Dict[str, Any]) -> bool:
        """
        Check if domain was registered for minimum period (< 1 year).
        Phishing domains are typically registered for the shortest period possible.
        """
        created = whois_data.get("creation_date") or whois_data.get("created")
        expiry = whois_data.get("expiration_date") or whois_data.get("registrar_registration_expiration_date")

        if created is None or expiry is None:
            return False

        if isinstance(created, list):
            created = min(created)
        if isinstance(expiry, list):
            expiry = min(expiry)

        if not isinstance(created, datetime) or not isinstance(expiry, datetime):
            return False

        registration_span = (expiry - created).days
        return registration_span < 400  # Less than ~13 months

    # --------------------
    # DNS helpers
    # --------------------

    def _query_dns(self, domain: str) -> tuple[bool, Optional[int]]:
        has_mx = False
        nameserver_count: Optional[int] = None

        try:
            answers = self._resolver.resolve(domain, "MX")
            has_mx = bool(answers)
        except Exception:
            has_mx = False

        try:
            answers = self._resolver.resolve(domain, "NS")
            nameserver_count = len(list(answers))
        except Exception:
            nameserver_count = None

        return has_mx, nameserver_count

    def _check_dnssec(self, domain: str) -> bool:
        """Check if the domain has DNSSEC enabled (DNSKEY records)."""
        try:
            answers = self._resolver.resolve(domain, "DNSKEY")
            return bool(answers)
        except Exception:
            return False

    # --------------------
    # Risk computation (graduated)
    # --------------------

    def _age_risk(self, age_days: Optional[int]) -> float:
        """Non-binary graduated risk based on domain age."""
        if age_days is None:
            return 0.15  # Unknown (WHOIS failed) = mild risk, not punitive
        if age_days < 7:
            return 0.50  # Brand new = very high
        if age_days < 30:
            return 0.35  # Less than a month
        if age_days < 90:
            return 0.15  # Less than 3 months
        if age_days < 365:
            return 0.05  # Less than a year
        return 0.0       # Established

    def _compute_risk_score(
        self,
        domain_age_days: Optional[int],
        is_new_domain: bool,
        is_hosted_platform: bool,
        whois_privacy_enabled: bool,
        has_mx_record: bool,
        nameserver_count: Optional[int],
        has_dnssec: bool,
        short_expiry: bool,
    ) -> float:
        # Primary signal: domain age (graduated)
        risk = self._age_risk(domain_age_days)
        
        # If WHOIS failed/unknown BUT we know it's a hosting platform, it's a huge risk
        # Threat actors massively abuse Vercel, Webflow, Pages.dev for free hosting
        if domain_age_days is None and is_hosted_platform:
            risk += 0.35  # Bumps the base 0.15 to a punitive 0.50 risk constraint

        # WHOIS privacy — only strongly risky when combined with new domain
        if whois_privacy_enabled:
            if is_new_domain:
                risk += 0.15  # Privacy + new = suspicious combo
            else:
                risk += 0.05  # Many legit sites use privacy

        # No MX records
        if not has_mx_record:
            risk += 0.10

        # Low nameserver count
        if nameserver_count is not None and nameserver_count <= 1:
            risk += 0.10

        # Short registration span
        if short_expiry:
            risk += 0.10

        # DNSSEC reduces risk slightly (legitimate infrastructure)
        if has_dnssec:
            risk = max(0.0, risk - 0.05)

        # Clamp to [0, 1]
        return max(0.0, min(1.0, risk))


__all__ = ["DomainIntelligenceAgent", "DomainIntelligenceResult"]
