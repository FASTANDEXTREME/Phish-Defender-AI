from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from rapidfuzz import fuzz
import tldextract

from agents.decision_agent import SimilarityAgentOutput


KNOWN_BRANDS: Dict[str, str] = {
    "google": "google.com",
    "paypal": "paypal.com",
    "facebook": "facebook.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "netflix": "netflix.com",
    "linkedin": "linkedin.com",
    "instagram": "instagram.com",
    "twitter": "twitter.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com"
}


HOMOGLYPH_MAP = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "@": "a",
        "3": "e",
        "5": "s",
        "7": "t",
    }
)


@dataclass(frozen=True)
class DomainSimilarityResult:
    input_domain: str
    root_domain: str
    normalized_domain: str
    brand_detected: bool
    brand_name: Optional[str]
    closest_brand: Optional[str]
    similarity_score: float
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
        # Allow caller to override or extend the brand set.
        self._brands = brands or KNOWN_BRANDS

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
            similarity_score = 0.0  # It's the actual brand, just a different TLD
        else:
            closest_brand, similarity_score = self._find_closest_brand(normalized_domain)

        risk_score = self._compute_risk_score(
            brand_detected=brand_detected,
            similarity_score=similarity_score,
            is_exact_brand=is_exact_brand
        )

        return DomainSimilarityResult(
            input_domain=input_value,
            root_domain=root_domain,
            normalized_domain=normalized_domain,
            brand_detected=brand_detected,
            brand_name=brand_name,
            closest_brand=closest_brand,
            similarity_score=similarity_score,
            risk_score=risk_score,
        )

    def _extract_root_domain(self, domain_or_url: str) -> str:
        ext = tldextract.extract(domain_or_url)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return ext.domain or domain_or_url

    def _normalize_domain(self, domain: str) -> str:
        """
        Replace common homograph characters to help catch impersonation.
        """
        return domain.translate(HOMOGLYPH_MAP)

    def _detect_brand_containment(self, normalized_domain: str) -> (Optional[str], bool):
        for brand in self._brands.keys():
            if brand in normalized_domain:
                return brand, True
        return None, False

    def _find_closest_brand(self, normalized_domain: str) -> (Optional[str], float):
        best_brand: Optional[str] = None
        best_score: float = 0.0

        for brand, legit_domain in self._brands.items():
            score = fuzz.ratio(normalized_domain, legit_domain) / 100.0
            if score > best_score:
                best_score = score
                best_brand = brand

        return best_brand, best_score

    def _compute_risk_score(self, brand_detected: bool, similarity_score: float, is_exact_brand: bool = False) -> float:
        """
        Compute risk from brand containment and fuzzy similarity.

        - Exact brand matches on the root domain with a valid TLD are considered safe (e.g. amazon.in).
        - Brand containment strongly increases risk (e.g. login-amazon.com).
        - Higher similarity scores increase risk smoothly.
        """
        if is_exact_brand:
            return 0.0
            
        risk = 0.0

        # Brand containment is a strong signal.
        if brand_detected:
            risk += 0.5

        # Similarity contribution (up to 0.5 additional risk).
        risk += min(similarity_score * 0.5, 0.5)

        # Clamp to [0, 1].
        return max(0.0, min(1.0, risk))


__all__ = ["DomainSimilarityAgent", "DomainSimilarityResult"]

