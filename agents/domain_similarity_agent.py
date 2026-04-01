"""
Domain Similarity Agent — detects brand impersonation, typosquatting,
homograph attacks, and phishing-keyword domain patterns.

Improvements over MVP:
- 75+ brands from centralized config
- Full Unicode homoglyph normalization (Cyrillic, IPA, ASCII look-alikes)
- Multi-algorithm fuzzy matching (ratio + partial_ratio + token_sort_ratio)
- Phishing keyword detection in domain names (login-paypal-secure.com)
- Proper handling of exact brand matches on alternate TLDs
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from rapidfuzz import fuzz
import tldextract

from agents.decision_agent import SimilarityAgentOutput
from core.config import (
    HOMOGLYPH_TRANSLATE,
    KNOWN_BRANDS,
    PHISHING_DOMAIN_KEYWORDS,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DomainSimilarityResult:
    input_domain: str
    root_domain: str
    normalized_domain: str
    brand_detected: bool
    brand_name: Optional[str]
    closest_brand: Optional[str]
    similarity_score: float
    phishing_keywords_in_domain: List[str]
    risk_score: float

    def to_dict(self) -> SimilarityAgentOutput:
        return {
            "input_domain": self.input_domain,
            "root_domain": self.root_domain,
            "normalized_domain": self.normalized_domain,
            "brand_detected": self.brand_name if self.brand_detected else None,
            "brand_name": self.brand_name,
            "closest_brand": self.closest_brand,
            "similarity_score": self.similarity_score,
            "risk_score": self.risk_score,
        }


class DomainSimilarityAgent:
    """
    Domain Similarity Agent for detecting brand impersonation, typosquatting,
    and homograph attacks.
    """

    def __init__(self, brands: Optional[Dict[str, str]] = None) -> None:
        self._brands = brands or KNOWN_BRANDS
        # Pre-compute normalized brand names for faster matching
        self._normalized_brands = {
            brand: brand.translate(HOMOGLYPH_TRANSLATE)
            for brand in self._brands
        }

    def run(self, domain_or_url: str) -> DomainSimilarityResult:
        input_value = domain_or_url.strip().lower()

        root_domain = self._extract_root_domain(input_value)
        normalized_domain = self._normalize_domain(root_domain)

        brand_name, brand_detected = self._detect_brand_containment(normalized_domain)

        # Check if the domain itself is exactly the brand name (e.g. "amazon" in "amazon.in")
        ext = tldextract.extract(input_value)
        is_exact_brand = ext.domain in self._brands

        if is_exact_brand:
            closest_brand = ext.domain
            similarity_score = 0.0
        else:
            closest_brand, similarity_score = self._find_closest_brand(normalized_domain)

        # Detect phishing keywords in the domain
        phishing_keywords = self._detect_phishing_keywords(root_domain)

        risk_score = self._compute_risk_score(
            brand_detected=brand_detected,
            similarity_score=similarity_score,
            is_exact_brand=is_exact_brand,
            phishing_keywords_count=len(phishing_keywords),
        )

        return DomainSimilarityResult(
            input_domain=input_value,
            root_domain=root_domain,
            normalized_domain=normalized_domain,
            brand_detected=brand_detected,
            brand_name=brand_name,
            closest_brand=closest_brand,
            similarity_score=similarity_score,
            phishing_keywords_in_domain=phishing_keywords,
            risk_score=risk_score,
        )

    def _extract_root_domain(self, domain_or_url: str) -> str:
        ext = tldextract.extract(domain_or_url)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return ext.domain or domain_or_url

    def _normalize_domain(self, domain: str) -> str:
        """Replace homograph characters (Unicode + ASCII look-alikes) to catch impersonation."""
        return domain.translate(HOMOGLYPH_TRANSLATE)

    def _detect_brand_containment(self, normalized_domain: str) -> Tuple[Optional[str], bool]:
        # Extract just the domain part (no TLD) for checking
        ext = tldextract.extract(normalized_domain)
        domain_part = ext.domain or normalized_domain.split(".")[0]

        for brand in self._brands:
            if brand in domain_part and brand != domain_part:
                # Short brands (≤3 chars) must appear as a standalone segment
                # e.g. "dhl" in "dhl-track" is valid, but "x" in "example" is not
                if len(brand) <= 3:
                    if not re.search(rf'(^|[-_.]){re.escape(brand)}([-_.]|$)', domain_part):
                        continue  # Substring match in longer word — skip
                return brand, True
        return None, False

    def _find_closest_brand(self, normalized_domain: str) -> Tuple[Optional[str], float]:
        """Multi-algorithm fuzzy matching for better typosquatting detection."""
        best_brand: Optional[str] = None
        best_score: float = 0.0

        ext = tldextract.extract(normalized_domain)
        domain_part = ext.domain or normalized_domain.split(".")[0]

        for brand, legit_domain in self._brands.items():
            # Full domain ratio
            full_ratio = fuzz.ratio(normalized_domain, legit_domain) / 100.0
            # Partial match — only for brands with length >= 4 to avoid
            # spurious matches (e.g. "steam" matching inside "startup")
            if len(brand) >= 4:
                partial = fuzz.partial_ratio(domain_part, brand) / 100.0
            else:
                partial = 0.0
            # Token sort (catches rearrangements)
            token_sort = fuzz.token_sort_ratio(normalized_domain, legit_domain) / 100.0

            # Combined score: take the best signal, weighted
            combined = max(full_ratio, partial * 0.9, token_sort * 0.85)

            if combined > best_score:
                best_score = combined
                best_brand = brand

        return best_brand, best_score

    def _detect_phishing_keywords(self, root_domain: str) -> List[str]:
        """Detect phishing-related keywords in the domain name itself."""
        ext = tldextract.extract(root_domain)
        domain_part = ext.domain or root_domain.split(".")[0]

        # Split on common delimiters
        parts = domain_part.replace("-", " ").replace("_", " ").replace(".", " ").lower()

        found = []
        for keyword in PHISHING_DOMAIN_KEYWORDS:
            if keyword in parts:
                found.append(keyword)
        return found

    def _compute_risk_score(
        self,
        brand_detected: bool,
        similarity_score: float,
        is_exact_brand: bool = False,
        phishing_keywords_count: int = 0,
    ) -> float:
        if is_exact_brand:
            return 0.0

        risk = 0.0

        # Brand containment is a strong signal
        if brand_detected:
            risk += 0.50

        # Similarity contribution — NON-LINEAR scaling
        # High similarity (>0.85) to a known brand is near-certain impersonation
        if similarity_score >= 0.85:
            risk += 0.75
        elif similarity_score >= 0.70:
            risk += 0.40
        elif similarity_score >= 0.50:
            risk += 0.20
        else:
            risk += similarity_score * 0.2  # Low similarity = low contribution

        # Phishing keywords in domain boost risk
        if phishing_keywords_count >= 2:
            risk += 0.15
        elif phishing_keywords_count == 1:
            risk += 0.05

        # Brand + phishing keyword combo is very suspicious
        if brand_detected and phishing_keywords_count > 0:
            risk += 0.10

        return max(0.0, min(1.0, risk))


__all__ = ["DomainSimilarityAgent", "DomainSimilarityResult"]
