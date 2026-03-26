from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import dns.resolver
import whois

from agents.decision_agent import DomainIntelligenceAgentOutput


@dataclass(frozen=True)
class DomainIntelligenceResult:
    input_domain: str
    domain_age_days: Optional[int]
    is_new_domain: bool
    whois_privacy_enabled: bool
    has_mx_record: bool
    nameserver_count: Optional[int]
    risk_score: float

    def to_dict(self) -> DomainIntelligenceAgentOutput:
        return {
            "domain_age_days": self.domain_age_days,
            "is_new_domain": self.is_new_domain,
            "whois_privacy_enabled": self.whois_privacy_enabled,
            "has_mx_record": self.has_mx_record,
            "nameserver_count": self.nameserver_count,
            "risk_score": self.risk_score,
        }


class DomainIntelligenceAgent:
    """
    Domain Intelligence Agent for the Intelligent Phishing Domain Detection system.

    Responsibilities:
    - Fetch WHOIS data and compute domain age.
    - Detect WHOIS privacy usage.
    - Query DNS for MX and NS records.
    - Compute an interpretable risk score from these signals.
    """

    # Risk contributions as defined in the master prompt
    NEW_DOMAIN_RISK: float = 0.5
    WHOIS_PRIVACY_RISK: float = 0.1
    NO_MX_RISK: float = 0.1
    LOW_NS_RISK: float = 0.1

    NEW_DOMAIN_THRESHOLD_DAYS: int = 30

    def __init__(
        self,
        whois_timeout: float = 5.0,
        dns_timeout: float = 3.0,
    ) -> None:
        self._whois_timeout = whois_timeout
        self._dns_timeout = dns_timeout

    def run(self, domain: str) -> DomainIntelligenceResult:
        """
        Main entry point for the agent.
        """
        safe_domain = domain.strip().lower()

        whois_data = self._safe_fetch_whois(safe_domain)
        domain_age_days = self._compute_domain_age_days(whois_data)
        is_new_domain = (
            domain_age_days is not None
            and domain_age_days < self.NEW_DOMAIN_THRESHOLD_DAYS
        )

        whois_privacy_enabled = self._detect_whois_privacy(whois_data)

        has_mx_record, nameserver_count = self._query_dns(safe_domain)

        risk_score = self._compute_risk_score(
            is_new_domain=is_new_domain,
            whois_privacy_enabled=whois_privacy_enabled,
            has_mx_record=has_mx_record,
            nameserver_count=nameserver_count,
        )

        return DomainIntelligenceResult(
            input_domain=safe_domain,
            domain_age_days=domain_age_days,
            is_new_domain=is_new_domain,
            whois_privacy_enabled=whois_privacy_enabled,
            has_mx_record=has_mx_record,
            nameserver_count=nameserver_count,
            risk_score=risk_score,
        )

    # --------------------
    # WHOIS helpers
    # --------------------

    def _safe_fetch_whois(self, domain: str) -> Dict[str, Any]:
        """
        Fetch WHOIS information defensively.
        """
        try:
            # python-whois does not expose an explicit timeout in all versions,
            # but we still keep this isolated to avoid propagating raw exceptions.
            data = whois.whois(domain)
            if isinstance(data, dict):
                return data
            # Some versions return a WHOIS object; convert to dict best‑effort
            return dict(data)  # type: ignore[arg-type]
        except Exception:
            # On any error, fall back to empty dict so the agent still returns a result
            return {}

    def _compute_domain_age_days(self, whois_data: Dict[str, Any]) -> Optional[int]:
        created = whois_data.get("creation_date") or whois_data.get("created")
        if created is None:
            return None

        # python-whois is inconsistent: creation_date may be a datetime or list[datetime]
        if isinstance(created, list):
            # Use the earliest creation date as the most conservative assumption
            created = min(created)

        if not isinstance(created, datetime):
            return None

        # Normalize to UTC and compute days
        now = datetime.now(timezone.utc)
        created_utc = created
        if created_utc.tzinfo is None:
            created_utc = created_utc.replace(tzinfo=timezone.utc)

        age_days = (now - created_utc).days
        return max(age_days, 0)

    def _detect_whois_privacy(self, whois_data: Dict[str, Any]) -> bool:
        privacy_indicators = (
            "privacy",
            "protect",
            "redacted",
            "whoisguard",
            "contact privacy",
        )

        text_chunks: list[str] = []
        for key, value in whois_data.items():
            if isinstance(value, str):
                text_chunks.append(value.lower())
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        text_chunks.append(item.lower())

        combined = " ".join(text_chunks)
        return any(indicator in combined for indicator in privacy_indicators)

    # --------------------
    # DNS helpers
    # --------------------

    def _query_dns(self, domain: str) -> tuple[bool, Optional[int]]:
        """
        Query DNS for MX and NS records using dnspython, with timeouts and safe error handling.
        """
        resolver = dns.resolver.Resolver()
        resolver.lifetime = self._dns_timeout
        resolver.timeout = self._dns_timeout

        has_mx = False
        nameserver_count: Optional[int] = None

        # MX records
        try:
            answers = resolver.resolve(domain, "MX")
            has_mx = bool(answers)
        except Exception:
            has_mx = False

        # NS records
        try:
            answers = resolver.resolve(domain, "NS")
            nameserver_count = len(list(answers))
        except Exception:
            nameserver_count = None

        return has_mx, nameserver_count

    # --------------------
    # Risk computation
    # --------------------

    def _compute_risk_score(
        self,
        is_new_domain: bool,
        whois_privacy_enabled: bool,
        has_mx_record: bool,
        nameserver_count: Optional[int],
    ) -> float:
        risk = 0.0

        if is_new_domain:
            risk += self.NEW_DOMAIN_RISK

        if whois_privacy_enabled:
            risk += self.WHOIS_PRIVACY_RISK

        if not has_mx_record:
            risk += self.NO_MX_RISK

        if nameserver_count is not None and nameserver_count <= 1:
            risk += self.LOW_NS_RISK

        # Clamp to [0, 0.8] as specified, then to [0, 1] for general safety
        risk = min(risk, 0.8)
        return max(0.0, min(1.0, risk))


__all__ = ["DomainIntelligenceAgent", "DomainIntelligenceResult"]

