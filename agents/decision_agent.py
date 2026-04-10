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
    SCORING_WEIGHTS_WITHOUT_SB_WITH_CRE,
    SUSPICIOUS_THRESHOLD,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Type aliases for agent outputs
# ---------------------------------------------------------------------------
ClassificationLabel = Literal["PHISHING", "SUSPICIOUS", "SAFE", "UNKNOWN"]
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
    ssl_valid: bool
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
    legitimate_app_behavior: bool
    risk_score: float
    # C1: Brand impersonation
    brand_impersonation_brands: List[str]
    # C6: Sensitive field detection
    payment_form_detected: bool
    scam_indicators_found: List[str]
    otp_detected: bool
    final_url: str
    final_domain: str
    is_provider_blocklisted: bool
    # C5: Playwright availability
    playwright_available: bool


class SafeBrowsingAgentOutput(TypedDict, total=False):
    input_domain: str
    is_safe: bool
    threat_matches: List[Dict[str, Any]]
    risk_score: float
    is_disabled: bool


class PhishTankAgentOutput(TypedDict, total=False):
    input_domain: str
    is_phishing: bool
    risk_score: float
    is_disabled: bool


class CrossReferenceOutput(TypedDict, total=False):
    brand_content_mismatch: bool
    brand_domain_mismatch: bool
    hosted_brand_impersonation: bool
    content_brand_names: List[str]
    domain_brand_name: str | None
    cross_ref_risk_score: float


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
    phishtank_risk: float
    cross_reference_risk: float
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
    raw_phishtank: PhishTankAgentOutput
    raw_cross_reference: CrossReferenceOutput

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_domain": self.input_domain,
            "similarity_risk": self.similarity_risk,
            "intelligence_risk": self.intelligence_risk,
            "content_risk": self.content_risk,
            "safe_browsing_risk": self.safe_browsing_risk,
            "phishtank_risk": self.phishtank_risk,
            "cross_reference_risk": self.cross_reference_risk,
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
            "raw_phishtank": self.raw_phishtank,
            "raw_cross_reference": self.raw_cross_reference,
        }


# ---------------------------------------------------------------------------
# Decision Agent
# ---------------------------------------------------------------------------
class DecisionAgent:
    """
    Aggregates output from Similarity, Domain Intelligence, Website Content,
    Safe Browsing, PhishTank, and Cross-Reference Engine to produce a
    final phishing classification.
    """

    def run(
        self,
        similarity: SimilarityAgentOutput,
        intelligence: DomainIntelligenceAgentOutput,
        content: WebsiteContentAgentOutput,
        safe_browsing: SafeBrowsingAgentOutput,
        phishtank: PhishTankAgentOutput,
        cross_reference: CrossReferenceOutput | None = None,
        network_state: str | None = None,
    ) -> DecisionAgentResult:

        input_domain = self._resolve_input_domain(similarity, intelligence, content, safe_browsing, phishtank)

        sim_risk = float(similarity.get("risk_score", 0.0) or 0.0)
        intel_risk = float(intelligence.get("risk_score", 0.0) or 0.0)
        content_risk = float(content.get("risk_score", 0.0) or 0.0)
        sb_risk = float(safe_browsing.get("risk_score", 0.0) or 0.0)
        pt_risk = float(phishtank.get("risk_score", 0.0) or 0.0)
        cre = cross_reference or {}
        cre_risk = float(cre.get("cross_ref_risk_score", 0.0) or 0.0)
        
        # -----------------------------------------------------------------
        # Trust Anchor Breaking (Domain Context Nullification)
        # -----------------------------------------------------------------
        from urllib.parse import urlparse
        import math
        from collections import Counter
        
        def shannon_entropy(data: str) -> float:
            if not data: return 0.0
            freq = Counter(data)
            return -sum((c/len(data)) * math.log2(c/len(data)) for c in freq.values())
        
        final_url = content.get("final_url", input_domain)
        path = urlparse(final_url if "://" in final_url else f"http://{final_url}").path
        path_entropy = shannon_entropy(path)
        
        is_trusted_anchor_broken = False
        if intel_risk < 0.15 and path_entropy > 4.2 and len([p for p in path.split('/') if p]) >= 3:
            logger.warning("Anchor Break: Trusted domain compromised. Nullifying intelligence safety score.")
            intel_risk = 0.50 # Overwrite the domain intelligence risk
            is_trusted_anchor_broken = True

        # -----------------------------------------------------------------
        # OVERRIDE: Google Safe Browsing is an authoritative trust layer
        # -----------------------------------------------------------------
        if not safe_browsing.get("is_safe", True):
            logger.warning("Safe Browsing override: %s flagged as malicious", input_domain)
            explanation_items = self._build_explanation_items(
                similarity, intelligence, content, safe_browsing, phishtank, cre, 1.0, "PHISHING", is_trusted_anchor_broken
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
                pt_risk=pt_risk,
                cre_risk=cre_risk,
                final_risk_score=1.0,
                classification="PHISHING",
                confidence="HIGH",
                severity="CRITICAL",
                explanation_items=explanation_items,
                similarity=similarity,
                intelligence=intelligence,
                content=content,
                safe_browsing=safe_browsing,
                phishtank=phishtank,
                cross_reference=cre,
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
            if cre_risk > 0.0:
                # CRE has a signal — use 4-way weights including cross-reference
                w = dict(SCORING_WEIGHTS_WITHOUT_SB_WITH_CRE)
                if intelligence.get("is_hosted_platform"):
                    w["intelligence"] = 0.05
                    w["similarity"] = 0.25
                    w["content"] = 0.35
                    w["cross_reference"] = 0.35
                score = (
                    sim_risk * w["similarity"]
                    + intel_risk * w["intelligence"]
                    + content_risk * w["content"]
                    + cre_risk * w["cross_reference"]
                )
            else:
                # No CRE signal — use existing 3-way weights
                w = dict(SCORING_WEIGHTS_WITHOUT_SB)
                if intelligence.get("is_hosted_platform"):
                    w["intelligence"] = 0.10
                    w["similarity"] = 0.40
                    w["content"] = 0.50
                score = (
                    sim_risk * w["similarity"]
                    + intel_risk * w["intelligence"]
                    + content_risk * w["content"]
                )

        # -----------------------------------------------------------------
        # Direct Combo Multipliers (Deadly Phishing Signatures)
        # -----------------------------------------------------------------
        # A brand new throwaway domain asking for login/password is a guaranteed flag
        has_login = content.get("login_form_detected") or content.get("password_field_detected")
        is_new = intelligence.get("is_new_domain")
        is_hosted = intelligence.get("is_hosted_platform")
        strong_sim = float(similarity.get("similarity_score", 0.0) or 0.0) > 0.60
        ssl_valid = intelligence.get("ssl_valid", False)
        legitimate_app = content.get("legitimate_app_behavior", False)
        domain_age = intelligence.get("domain_age_days")
        
        # FP-Fix: Check if domain similarity agent already identified this as a known alias
        # If sim_risk is 0.0 and brand_detected, this is a known sub-brand — skip most combos
        is_known_alias = (sim_risk == 0.0 and similarity.get("brand_detected") is not None)
        
        # Combo 1: New Domain + Login Form
        if is_new and has_login:
            logger.info("Combo detected: New domain + Login Form -> %s", input_domain)
            score += 0.20
        
        # Combo 2: Suspicious Hosting Platform + Login Form + Brand Similarity
        if is_hosted and has_login and strong_sim:
            logger.info("Combo detected: Hosting + Login Form + Similarity -> %s", input_domain)
            score += 0.25

        # Combo 3: Obvious Impersonation (Strong Sim) on a Hosted Platform
        if strong_sim and is_hosted:
            logger.info("Combo detected: Impersonation on Hosted Platform -> %s", input_domain)
            score += 0.20

        # Combo 3.5: Open Redirect / Provider Blocklisting
        final_domain = content.get("final_domain", "")
        # If the page actually served ends up on a vastly different domain and has a login form
        # (Exclude subdomains, e.g., 'auth.google.com' vs 'google.com')
        # FP-Fix: Also exclude redirects to known brand family domains
        if final_domain and final_domain != input_domain:
            if final_domain.split('.')[-2:] != input_domain.split('.')[-2:]:
                # Check if redirect is to a known family domain (e.g. amazonaws.com → aws.amazon.com)
                from core.config import BRAND_DOMAIN_ALIASES
                import tldextract as _tld
                _in_ext = _tld.extract(input_domain)
                _fin_ext = _tld.extract(final_domain)
                _in_root = f"{_in_ext.domain}.{_in_ext.suffix}" if _in_ext.suffix else _in_ext.domain
                _fin_root = f"{_fin_ext.domain}.{_fin_ext.suffix}" if _fin_ext.suffix else _fin_ext.domain
                is_family_redirect = False
                for _canon, _aliases in BRAND_DOMAIN_ALIASES.items():
                    _all = [_canon] + _aliases
                    _all_roots = set()
                    for _d in _all:
                        _de = _tld.extract(_d)
                        _all_roots.add(f"{_de.domain}.{_de.suffix}" if _de.suffix else _de.domain)
                    if _in_root in _all_roots and _fin_root in _all_roots:
                        is_family_redirect = True
                        break
                if has_login and not is_family_redirect:
                    logger.info("Combo detected: Open Redirect with Login Form -> final_domain=%s", final_domain)
                    score += 0.35

        # Provider blocklisting triggers immediate CRITICAL scoring (shorteners with block pages)
        if content.get("is_provider_blocklisted"):
            logger.info("Combo detected: Provider explicitly blocked this link -> %s", input_domain)
            score = 1.0

        # Combo 4: Pure impersonation (Sim risk very high)
        # FP-Fix: Only apply if NOT a known alias (prevents discord.gg, github.io etc.)
        if sim_risk >= 0.75 and not is_known_alias:
            logger.info("Combo detected: Very high similarity risk -> %s", input_domain)
            score += 0.20

        # Combo 5: Explicit Login form detected on ANY suspicious intelligence
        if has_login and (intel_risk >= 0.40):
            logger.info("Combo detected: Login Form with Suspicious Intelligence -> %s", input_domain)
            score += 0.15

        # NOTE: Combos 6-9 (brand impersonation, payment on hosted, scam indicators)
        # have been moved to the Cross-Reference Engine (core/cross_reference_engine.py).
        # The CRE score is already integrated into the weighted score above.
        brand_impersonation = content.get("brand_impersonation_brands", [])
        has_payment = content.get("payment_form_detected", False)
        scam_indicators = content.get("scam_indicators_found", [])

        # -----------------------------------------------------------------
        # PhishTank Override (High Suspicion / High Risk)
        # -----------------------------------------------------------------
        if phishtank.get("is_phishing", False):
            logger.warning("PhishTank override: %s flagged", input_domain)
            score = max(0.54, score)  # FP-Fix: Raised floor to match new PHISHING_THRESHOLD
            
            # Note: We append the item manually to the explanation items array later, 
            # or rely on `_build_explanation_items` below so we don't duplicate.

        # -----------------------------------------------------------------
        # Graceful Degradation (Positive Signals)
        # FP-Fix: Strengthened legitimate app reduction. If the page looks like a
        # legitimate application (no forms, no keywords, good title) with valid SSL
        # and no agents flagging high risk, apply a stronger score reduction.
        # -----------------------------------------------------------------
        any_agent_high_risk = any(r >= 0.40 for r in [sim_risk, intel_risk, content_risk, cre_risk])
        has_critical_signals = bool(brand_impersonation) or has_payment or len(scam_indicators) >= 2 or cre_risk >= 0.50
        
        # NEVER apply legitimate app reductions to Hosted App Builders (they have 0 inherent phishing defense)
        # or domains blocked by providers.
        if is_hosted or content.get("is_provider_blocklisted"):
            legitimate_app = False

        # FP-Fix: Established domain trust signal — domains >2yr with SSL get positive treatment
        is_established_domain = (
            domain_age is not None
            and domain_age > 730
            and ssl_valid
            and not is_new
            and not is_hosted
        )

        if legitimate_app and ssl_valid and not any_agent_high_risk and not has_critical_signals:
            logger.info("Graceful degradation: legitimate behavior and valid SSL -> %s", input_domain)
            score = max(0.0, score - 0.15)  # FP-Fix: increased from -0.10 → -0.15
        elif legitimate_app and not any_agent_high_risk and not has_critical_signals:
            score = max(0.0, score - 0.08)  # FP-Fix: increased from -0.05 → -0.08

        # FP-Fix: Established domain bonus — old well-known domains get a trust discount
        if is_established_domain and not has_critical_signals and score > 0:
            old_score = score
            score = max(0.0, score - 0.10)
            logger.info("Established domain trust: %.2f → %.2f for %s (age: %s days)", old_score, score, input_domain, domain_age)

        # Signal amplification — when multiple agents agree on high risk
        # Lowered threshold from 0.5 to 0.4 so combinations of mid-risk signals still trigger the boost
        high_risk_agents = sum(
            1 for r in [sim_risk, intel_risk, content_risk, cre_risk] if r >= 0.40
        )
        if high_risk_agents >= CORROBORATION_THRESHOLD:
            logger.info("Corroboration: %d agents >= 0.40 -> Applying boost for %s", high_risk_agents, input_domain)
            score = min(1.0, score * CORROBORATION_BOOST)

        score = max(0.0, min(1.0, score))

        if network_state == "BLOCKED":
            score = min(score, 0.60)

        classification = self._classify(score, is_new, is_hosted, network_state)
        confidence = self._compute_confidence(score, classification)
        severity = self._compute_severity(score, classification, safe_browsing)

        explanation_items = self._build_explanation_items(
            similarity, intelligence, content, safe_browsing, phishtank, cre, score, classification, is_trusted_anchor_broken
        )

        return self._build_result(
            input_domain=input_domain,
            sim_risk=sim_risk,
            intel_risk=intel_risk,
            content_risk=content_risk,
            sb_risk=sb_risk,
            pt_risk=pt_risk,
            cre_risk=cre_risk,
            final_risk_score=round(score, 4),
            classification=classification,
            confidence=confidence,
            severity=severity,
            explanation_items=explanation_items,
            similarity=similarity,
            intelligence=intelligence,
            content=content,
            safe_browsing=safe_browsing,
            phishtank=phishtank,
            cross_reference=cre,
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

    def _classify(self, score: float, is_new: bool, is_hosted: bool, network_state: str | None) -> ClassificationLabel:
        if network_state in ("BLOCKED", "UNREACHABLE", "ERROR"):
            return "UNKNOWN"
            
        # FP-Fix: Use consistent thresholds based on domain type.
        # The old code used 0.35 for new/hosted which was far too aggressive.
        phishing_threshold = PHISHING_THRESHOLD  # 0.55 (base)
        if is_new or is_hosted:
            phishing_threshold = 0.45  # FP-Fix: Was 0.35 — still lower than base for untrusted domains
        elif not is_new and not is_hosted:
            phishing_threshold = PHISHING_THRESHOLD  # 0.55 for established domains

        if score >= phishing_threshold:
            return "PHISHING"
        if score >= SUSPICIOUS_THRESHOLD:
            return "SUSPICIOUS"
        return "SAFE"

    def _compute_confidence(self, score: float, label: ClassificationLabel) -> ConfidenceLabel:
        """Score-based confidence instead of label-based."""
        if label == "UNKNOWN":
            return "LOW"
        if label == "SAFE":
            return "HIGH" if score < 0.1 else "MEDIUM"
        if label == "PHISHING":
            return "HIGH" if score >= min(1.0, PHISHING_THRESHOLD + 0.15) else "MEDIUM"
        # SUSPICIOUS
        midpoint = SUSPICIOUS_THRESHOLD + ((PHISHING_THRESHOLD - SUSPICIOUS_THRESHOLD) / 2.0)
        return "MEDIUM" if score >= midpoint else "LOW"

    def _compute_severity(
        self, score: float, label: ClassificationLabel, sb: SafeBrowsingAgentOutput
    ) -> SeverityLabel:
        if not sb.get("is_safe", True):
            return "CRITICAL"
        if label == "PHISHING" and score >= min(1.0, PHISHING_THRESHOLD + 0.15):
            return "HIGH"
        if label == "PHISHING":
            return "MEDIUM"
        if label == "SUSPICIOUS":
            return "LOW"
        if label == "UNKNOWN":
            return "INFO"
        return "INFO"

    def _build_result(
        self,
        *,
        input_domain: str,
        sim_risk: float,
        intel_risk: float,
        content_risk: float,
        sb_risk: float,
        pt_risk: float,
        cre_risk: float,
        final_risk_score: float,
        classification: ClassificationLabel,
        confidence: ConfidenceLabel,
        severity: SeverityLabel,
        explanation_items: List[ExplanationItem],
        similarity: SimilarityAgentOutput,
        intelligence: DomainIntelligenceAgentOutput,
        content: WebsiteContentAgentOutput,
        safe_browsing: SafeBrowsingAgentOutput,
        phishtank: PhishTankAgentOutput,
        cross_reference: CrossReferenceOutput,
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
            phishtank_risk=pt_risk,
            cross_reference_risk=cre_risk,
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
            raw_phishtank=phishtank,
            raw_cross_reference=cross_reference,
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
        phishtank: PhishTankAgentOutput,
        cross_reference: CrossReferenceOutput,
        final_score: float,
        classification: ClassificationLabel,
        is_trusted_anchor_broken: bool = False,
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

        # --- PhishTank ---
        if phishtank.get("is_phishing", False):
            items.append(ExplanationItem(
                category="phishtank",
                signal="CRITICAL: PhishTank database flagged this URL as a high risk link.",
                impact="high",
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
            domain_name = self._resolve_input_domain(similarity, intelligence, content, safe_browsing, phishtank)
            if len([p for p in domain_name.split('.') if p]) <= 2:
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

        if intelligence.get("ssl_valid"):
            items.append(ExplanationItem(
                category="intelligence",
                signal="Domain has a valid SSL certificate.",
                impact="low",  # positive impact, but kept visually as info
            ))
        else:
            items.append(ExplanationItem(
                category="intelligence",
                signal="Domain lacks a valid SSL certificate.",
                impact="medium",
            ))

        if is_trusted_anchor_broken:
            items.append(ExplanationItem(
                category="intelligence",
                signal="CRITICAL: Trusted domain exhibits deep, high-entropy randomized paths (possible compromised site). Nullified domain safety score.",
                impact="high",
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

        if content.get("legitimate_app_behavior"):
            items.append(ExplanationItem(
                category="content",
                signal="Page structure and behavior appear legitimate (safe content).",
                impact="low",  # positive
            ))

        # --- C1: Brand impersonation (content-level signal) ---
        impersonated_brands = content.get("brand_impersonation_brands", [])
        if impersonated_brands:
            brands_str = ", ".join(impersonated_brands[:5])
            items.append(ExplanationItem(
                category="content",
                signal=f"BRAND IMPERSONATION: Page content references brand(s) [{brands_str}] but domain does not match.",
                impact="critical",
            ))

        # --- Cross-Reference Engine ---
        if cross_reference:
            cre_score = float(cross_reference.get("cross_ref_risk_score", 0.0) or 0.0)
            if cross_reference.get("hosted_brand_impersonation"):
                items.append(ExplanationItem(
                    category="cross_reference",
                    signal="CRITICAL: Cross-Reference Engine detected brand impersonation on a hosted platform — all signals align.",
                    impact="critical",
                ))
            elif cross_reference.get("brand_content_mismatch") and not impersonated_brands:
                cre_brands = ", ".join((cross_reference.get("content_brand_names") or [])[:3])
                items.append(ExplanationItem(
                    category="cross_reference",
                    signal=f"Cross-reference analysis: page references brand(s) [{cre_brands}] on a non-matching domain.",
                    impact="high",
                ))
            elif cross_reference.get("brand_domain_mismatch"):
                items.append(ExplanationItem(
                    category="cross_reference",
                    signal=f"Cross-reference analysis: domain name contains brand '{cross_reference.get('domain_brand_name', '?')}' on a hosted platform.",
                    impact="high",
                ))
            if cre_score > 0.0 and not cross_reference.get("hosted_brand_impersonation"):
                items.append(ExplanationItem(
                    category="cross_reference",
                    signal=f"Cross-Reference Engine risk score: {cre_score:.2f}",
                    impact="high" if cre_score >= 0.65 else "medium",
                ))

        # --- C6: Payment form ---
        if content.get("payment_form_detected"):
            items.append(ExplanationItem(
                category="content",
                signal="Payment/credit card collection form detected on the page.",
                impact="high",
            ))

        # --- C6: Scam indicators ---
        scam_indicators = content.get("scam_indicators_found", [])
        if scam_indicators:
            sample = ", ".join(scam_indicators[:3])
            items.append(ExplanationItem(
                category="content",
                signal=f"Tech support scam indicators detected: {sample}.",
                impact="high",
            ))

        # --- C6: OTP detection ---
        if content.get("otp_detected"):
            items.append(ExplanationItem(
                category="content",
                signal="OTP / verification code input detected on the page.",
                impact="medium",
            ))

        # --- C5: Playwright unavailable ---
        if not content.get("playwright_available", True) and content.get("page_reachable", False):
            items.append(ExplanationItem(
                category="content",
                signal="⚠️ Playwright unavailable — JS-rendered content was NOT analyzed (detection may be incomplete).",
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
    "PhishTankAgentOutput",
    "CrossReferenceOutput",
    "DecisionAgentResult",
    "DecisionAgent",
    "ExplanationItem",
]
