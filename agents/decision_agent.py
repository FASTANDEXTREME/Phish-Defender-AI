"""
Decision Agent — aggregates outputs from all upstream agents and produces a
final phishing classification with human-readable explanations.

Key improvements over the MVP:
- Google Safe Browsing override (flagged → PHISHING at max confidence)
- Score-based confidence (not label-based)
- Signal amplification when multiple agents agree
- Severity levels (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- Structured explanations with impact tags
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, TypedDict

from core.config import (
    CORROBORATION_BOOST,
    CORROBORATION_THRESHOLD,
    PHISHING_THRESHOLD,
    SCORING_WEIGHTS_WITH_SB,
    SCORING_WEIGHTS_WITHOUT_SB,
    SUSPICIOUS_THRESHOLD,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Type aliases for agent outputs
# ---------------------------------------------------------------------------
ClassificationLabel = Literal["PHISHING", "SUSPICIOUS", "SAFE"]
ConfidenceLabel = Literal["HIGH", "MEDIUM", "LOW"]
SeverityLabel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class SimilarityAgentOutput(TypedDict, total=False):
    input_domain: str
    risk_score: float
    similarity_score: float
    brand_detected: str | None
    root_domain: str
    normalized_domain: str
    brand_name: str | None
    closest_brand: str | None


class DomainIntelligenceAgentOutput(TypedDict, total=False):
    domain_age_days: int | None
    is_new_domain: bool
    whois_privacy_enabled: bool
    has_mx_record: bool
    nameserver_count: int | None
    has_dnssec: bool
    short_expiry: bool
    risk_score: float


class WebsiteContentAgentOutput(TypedDict, total=False):
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
    risk_score: float


class SafeBrowsingAgentOutput(TypedDict, total=False):
    input_domain: str
    is_safe: bool
    threat_matches: List[Dict[str, Any]]
    risk_score: float


# ---------------------------------------------------------------------------
# Structured explanation item
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ExplanationItem:
    category: str   # "similarity", "intelligence", "content", "safe_browsing"
    signal: str     # Human-readable description
    impact: str     # "critical", "high", "medium", "low"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DecisionAgentResult:
    input_domain: str
    similarity_risk: float
    intelligence_risk: float
    content_risk: float
    safe_browsing_risk: float
    final_risk_score: float
    classification: ClassificationLabel
    confidence: ConfidenceLabel
    severity: SeverityLabel
    explanation: List[str]
    explanation_details: List[Dict[str, str]]
    raw_similarity: SimilarityAgentOutput
    raw_intelligence: DomainIntelligenceAgentOutput
    raw_content: WebsiteContentAgentOutput
    raw_safe_browsing: SafeBrowsingAgentOutput

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_domain": self.input_domain,
            "similarity_risk": self.similarity_risk,
            "intelligence_risk": self.intelligence_risk,
            "content_risk": self.content_risk,
            "safe_browsing_risk": self.safe_browsing_risk,
            "final_risk_score": self.final_risk_score,
            "classification": self.classification,
            "confidence": self.confidence,
            "severity": self.severity,
            "explanation": self.explanation,
            "explanation_details": self.explanation_details,
            "raw_similarity": self.raw_similarity,
            "raw_intelligence": self.raw_intelligence,
            "raw_content": self.raw_content,
            "raw_safe_browsing": self.raw_safe_browsing,
        }


# ---------------------------------------------------------------------------
# Decision Agent
# ---------------------------------------------------------------------------
class DecisionAgent:
    """
    Aggregates output from Similarity, Domain Intelligence, Website Content,
    and Safe Browsing agents to produce a final phishing classification.
    """

    def run(
        self,
        similarity: SimilarityAgentOutput,
        intelligence: DomainIntelligenceAgentOutput,
        content: WebsiteContentAgentOutput,
        safe_browsing: SafeBrowsingAgentOutput,
    ) -> DecisionAgentResult:

        input_domain = self._resolve_input_domain(similarity, intelligence, content, safe_browsing)

        sim_risk = float(similarity.get("risk_score", 0.0) or 0.0)
        intel_risk = float(intelligence.get("risk_score", 0.0) or 0.0)
        content_risk = float(content.get("risk_score", 0.0) or 0.0)
        sb_risk = float(safe_browsing.get("risk_score", 0.0) or 0.0)

        # -----------------------------------------------------------------
        # OVERRIDE: Google Safe Browsing is an authoritative trust layer
        # -----------------------------------------------------------------
        if not safe_browsing.get("is_safe", True):
            logger.warning("Safe Browsing override: %s flagged as malicious", input_domain)
            explanation_items = self._build_explanation_items(
                similarity, intelligence, content, safe_browsing, 1.0, "PHISHING"
            )
            # Prepend the critical override message
            override_item = ExplanationItem(
                category="safe_browsing",
                signal="CRITICAL: Google Safe Browsing flagged this URL as malicious. "
                       "Classification overridden to PHISHING with maximum confidence.",
                impact="critical",
            )
            explanation_items.insert(0, override_item)

            return self._build_result(
                input_domain=input_domain,
                sim_risk=sim_risk,
                intel_risk=intel_risk,
                content_risk=content_risk,
                sb_risk=sb_risk,
                final_risk_score=1.0,
                classification="PHISHING",
                confidence="HIGH",
                severity="CRITICAL",
                explanation_items=explanation_items,
                similarity=similarity,
                intelligence=intelligence,
                content=content,
                safe_browsing=safe_browsing,
            )

        # -----------------------------------------------------------------
        # Normal weighted scoring path
        # Dynamic weight redistribution: when SB returns safe (risk=0.0),
        # its weight is dead weight. Redistribute to other agents.
        # -----------------------------------------------------------------
        if sb_risk > 0.0:
            w = SCORING_WEIGHTS_WITH_SB
            score = (
                sim_risk * w["similarity"]
                + intel_risk * w["intelligence"]
                + content_risk * w["content"]
                + sb_risk * w["safe_browsing"]
            )
        else:
            w = SCORING_WEIGHTS_WITHOUT_SB
            score = (
                sim_risk * w["similarity"]
                + intel_risk * w["intelligence"]
                + content_risk * w["content"]
            )

        # Signal amplification — when multiple agents agree on high risk
        high_risk_agents = sum(
            1 for r in [sim_risk, intel_risk, content_risk] if r >= 0.5
        )
        if high_risk_agents >= CORROBORATION_THRESHOLD:
            score = min(1.0, score * CORROBORATION_BOOST)

        score = max(0.0, min(1.0, score))

        classification = self._classify(score)
        confidence = self._compute_confidence(score, classification)
        severity = self._compute_severity(score, classification, safe_browsing)

        explanation_items = self._build_explanation_items(
            similarity, intelligence, content, safe_browsing, score, classification
        )

        return self._build_result(
            input_domain=input_domain,
            sim_risk=sim_risk,
            intel_risk=intel_risk,
            content_risk=content_risk,
            sb_risk=sb_risk,
            final_risk_score=round(score, 4),
            classification=classification,
            confidence=confidence,
            severity=severity,
            explanation_items=explanation_items,
            similarity=similarity,
            intelligence=intelligence,
            content=content,
            safe_browsing=safe_browsing,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_input_domain(self, *sources) -> str:
        for source in sources:
            domain = source.get("input_domain") if isinstance(source, dict) else None
            if isinstance(domain, str) and domain:
                return domain
        return ""

    def _classify(self, score: float) -> ClassificationLabel:
        if score >= PHISHING_THRESHOLD:
            return "PHISHING"
        if score >= SUSPICIOUS_THRESHOLD:
            return "SUSPICIOUS"
        return "SAFE"

    def _compute_confidence(self, score: float, label: ClassificationLabel) -> ConfidenceLabel:
        """Score-based confidence instead of label-based."""
        if label == "SAFE":
            return "HIGH" if score < 0.1 else "MEDIUM"
        if label == "PHISHING":
            return "HIGH" if score >= 0.85 else "MEDIUM"
        # SUSPICIOUS
        return "MEDIUM" if score >= 0.55 else "LOW"

    def _compute_severity(
        self, score: float, label: ClassificationLabel, sb: SafeBrowsingAgentOutput
    ) -> SeverityLabel:
        if not sb.get("is_safe", True):
            return "CRITICAL"
        if label == "PHISHING" and score >= 0.85:
            return "HIGH"
        if label == "PHISHING":
            return "MEDIUM"
        if label == "SUSPICIOUS":
            return "LOW"
        return "INFO"

    def _build_result(
        self,
        *,
        input_domain: str,
        sim_risk: float,
        intel_risk: float,
        content_risk: float,
        sb_risk: float,
        final_risk_score: float,
        classification: ClassificationLabel,
        confidence: ConfidenceLabel,
        severity: SeverityLabel,
        explanation_items: List[ExplanationItem],
        similarity: SimilarityAgentOutput,
        intelligence: DomainIntelligenceAgentOutput,
        content: WebsiteContentAgentOutput,
        safe_browsing: SafeBrowsingAgentOutput,
    ) -> DecisionAgentResult:
        # Build both a flat human-readable list and a structured detail list
        explanation_strings = [item.signal for item in explanation_items]
        explanation_details = [
            {"category": item.category, "signal": item.signal, "impact": item.impact}
            for item in explanation_items
        ]

        return DecisionAgentResult(
            input_domain=input_domain,
            similarity_risk=sim_risk,
            intelligence_risk=intel_risk,
            content_risk=content_risk,
            safe_browsing_risk=sb_risk,
            final_risk_score=final_risk_score,
            classification=classification,
            confidence=confidence,
            severity=severity,
            explanation=explanation_strings,
            explanation_details=explanation_details,
            raw_similarity=similarity,
            raw_intelligence=intelligence,
            raw_content=content,
            raw_safe_browsing=safe_browsing,
        )

    # ------------------------------------------------------------------
    # Explanation builder
    # ------------------------------------------------------------------

    def _build_explanation_items(
        self,
        similarity: SimilarityAgentOutput,
        intelligence: DomainIntelligenceAgentOutput,
        content: WebsiteContentAgentOutput,
        safe_browsing: SafeBrowsingAgentOutput,
        final_score: float,
        classification: ClassificationLabel,
    ) -> List[ExplanationItem]:
        items: List[ExplanationItem] = []

        # Overall summary
        items.append(ExplanationItem(
            category="overall",
            signal=f"Final risk score {final_score:.2f} → classified as {classification}.",
            impact="high" if classification == "PHISHING" else "medium" if classification == "SUSPICIOUS" else "low",
        ))

        # --- Safe Browsing ---
        if not safe_browsing.get("is_safe", True):
            items.append(ExplanationItem(
                category="safe_browsing",
                signal="Google Safe Browsing flagged this URL as malicious.",
                impact="critical",
            ))

        # --- Similarity ---
        brand = similarity.get("brand_detected")
        sim_score = similarity.get("similarity_score")

        if brand and sim_score is not None and sim_score >= 0.7:
            items.append(ExplanationItem(
                category="similarity",
                signal=f"Domain resembles known brand '{brand}' with similarity {sim_score:.0%}.",
                impact="high",
            ))
        elif sim_score is not None and sim_score >= 0.7:
            items.append(ExplanationItem(
                category="similarity",
                signal=f"Domain is highly similar to a known domain (similarity {sim_score:.0%}).",
                impact="high",
            ))
        elif brand:
            items.append(ExplanationItem(
                category="similarity",
                signal=f"Domain contains brand name '{brand}' in a suspicious context.",
                impact="medium",
            ))

        # --- Intelligence ---
        age = intelligence.get("domain_age_days")
        if intelligence.get("is_new_domain"):
            age_str = f" ({age} days old)" if age is not None else ""
            items.append(ExplanationItem(
                category="intelligence",
                signal=f"Domain registered very recently{age_str}.",
                impact="high",
            ))
        elif age is not None and age < 365:
            items.append(ExplanationItem(
                category="intelligence",
                signal=f"Domain is relatively young ({age} days old).",
                impact="medium",
            ))

        if intelligence.get("whois_privacy_enabled"):
            items.append(ExplanationItem(
                category="intelligence",
                signal="WHOIS privacy is enabled, hiding registrant information.",
                impact="medium" if intelligence.get("is_new_domain") else "low",
            ))

        if not intelligence.get("has_mx_record", True):
            items.append(ExplanationItem(
                category="intelligence",
                signal="Domain has no MX (mail) records — unusual for legitimate domains.",
                impact="medium",
            ))

        ns_count = intelligence.get("nameserver_count")
        if isinstance(ns_count, int) and ns_count < 2:
            items.append(ExplanationItem(
                category="intelligence",
                signal=f"Low nameserver redundancy (count={ns_count}).",
                impact="low",
            ))

        if intelligence.get("short_expiry"):
            items.append(ExplanationItem(
                category="intelligence",
                signal="Domain registered for minimum period (< 1 year) — common in throwaway phishing domains.",
                impact="medium",
            ))

        # --- Content ---
        if not content.get("page_reachable", True):
            items.append(ExplanationItem(
                category="content",
                signal="Website is not reachable.",
                impact="low",
            ))

        if content.get("login_form_detected") or content.get("password_field_detected"):
            items.append(ExplanationItem(
                category="content",
                signal="Login or password input form detected on the page.",
                impact="medium",
            ))

        cross_domain = content.get("cross_domain_forms", 0)
        if cross_domain > 0:
            items.append(ExplanationItem(
                category="content",
                signal=f"Form submits data to a different domain ({cross_domain} cross-domain form(s)).",
                impact="high",
            ))

        keywords = content.get("suspicious_keywords_found") or []
        if keywords:
            sample = ", ".join(keywords[:5])
            items.append(ExplanationItem(
                category="content",
                signal=f"Phishing-related keywords detected: {sample}.",
                impact="medium",
            ))

        ext_scripts = content.get("external_scripts_count")
        if isinstance(ext_scripts, int) and ext_scripts > 10:
            items.append(ExplanationItem(
                category="content",
                signal=f"High number of external scripts ({ext_scripts}).",
                impact="low",
            ))

        if content.get("suspicious_iframes", 0) > 0:
            items.append(ExplanationItem(
                category="content",
                signal="Suspicious iframe(s) embedding external content.",
                impact="medium",
            ))

        if content.get("has_meta_refresh") or content.get("has_js_redirect"):
            items.append(ExplanationItem(
                category="content",
                signal="Page contains redirect mechanisms (meta-refresh or JavaScript redirect).",
                impact="medium",
            ))

        # Fallback
        if len(items) == 1:
            items.append(ExplanationItem(
                category="overall",
                signal="No strong individual red flags; classification based on combined risk scores.",
                impact="low",
            ))

        return items


__all__ = [
    "SimilarityAgentOutput",
    "DomainIntelligenceAgentOutput",
    "WebsiteContentAgentOutput",
    "SafeBrowsingAgentOutput",
    "DecisionAgentResult",
    "DecisionAgent",
    "ExplanationItem",
]
