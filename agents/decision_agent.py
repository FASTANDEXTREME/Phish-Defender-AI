from dataclasses import dataclass
from typing import Any, Dict, List, Literal, TypedDict


ClassificationLabel = Literal["PHISHING", "SUSPICIOUS", "SAFE"]
ConfidenceLabel = Literal["HIGH", "MEDIUM", "LOW"]


class SimilarityAgentOutput(TypedDict, total=False):
    # Core fields consumed by the Decision Agent / RSC Agent
    input_domain: str
    risk_score: float
    similarity_score: float
    brand_detected: str | None

    # Additional fields produced by the Domain Similarity Agent
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
    risk_score: float


class WebsiteContentAgentOutput(TypedDict, total=False):
    input_domain: str
    page_reachable: bool
    login_form_detected: bool
    password_field_detected: bool
    suspicious_keywords_found: List[str]
    external_scripts_count: int
    forms_count: int
    risk_score: float

class SafeBrowsingAgentOutput(TypedDict, total=False):
    input_domain: str
    is_safe: bool
    threat_matches: List[Dict[str, Any]]
    risk_score: float


@dataclass(frozen=True)
class DecisionAgentResult:
    """
    Structured output of the Decision Agent.
    """

    input_domain: str
    similarity_risk: float
    intelligence_risk: float
    content_risk: float
    final_risk_score: float
    classification: ClassificationLabel
    confidence: ConfidenceLabel
    explanation: List[str]
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
            "final_risk_score": self.final_risk_score,
            "classification": self.classification,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "raw_similarity": self.raw_similarity,
            "raw_intelligence": self.raw_intelligence,
            "raw_content": self.raw_content,
            "raw_safe_browsing": self.raw_safe_browsing,
        }


class DecisionAgent:
    """
    Aggregates output from the Similarity, Domain Intelligence and Website Content agents
    to produce a final phishing classification.
    """

    # Weights for each agent's risk contribution
    SIMILARITY_WEIGHT: float = 0.3
    INTELLIGENCE_WEIGHT: float = 0.2
    CONTENT_WEIGHT: float = 0.2
    SAFE_BROWSING_WEIGHT: float = 0.3

    # Thresholds for classification
    PHISHING_THRESHOLD: float = 0.7
    SUSPICIOUS_THRESHOLD: float = 0.4

    def run(
        self,
        similarity: SimilarityAgentOutput,
        intelligence: DomainIntelligenceAgentOutput,
        content: WebsiteContentAgentOutput,
        safe_browsing: SafeBrowsingAgentOutput,
    ) -> DecisionAgentResult:
        """
        Main entry point for the Decision Agent.
        """
        input_domain = self._resolve_input_domain(similarity, intelligence, content, safe_browsing)

        similarity_risk = float(similarity.get("risk_score", 0.0) or 0.0)
        intelligence_risk = float(intelligence.get("risk_score", 0.0) or 0.0)
        content_risk = float(content.get("risk_score", 0.0) or 0.0)
        sb_risk = float(safe_browsing.get("risk_score", 0.0) or 0.0)

        final_risk_score = self._compute_final_risk(
            similarity_risk, intelligence_risk, content_risk, sb_risk
        )
        classification = self._classify(final_risk_score)
        confidence = self._confidence_for_classification(classification)
        explanation = self._build_explanation(
            similarity=similarity,
            intelligence=intelligence,
            content=content,
            safe_browsing=safe_browsing,
            final_risk_score=final_risk_score,
            classification=classification,
        )

        return DecisionAgentResult(
            input_domain=input_domain,
            similarity_risk=similarity_risk,
            intelligence_risk=intelligence_risk,
            content_risk=content_risk,
            final_risk_score=final_risk_score,
            classification=classification,
            confidence=confidence,
            explanation=explanation,
            raw_similarity=similarity,
            raw_intelligence=intelligence,
            raw_content=content,
            raw_safe_browsing=safe_browsing,
        )

    def _resolve_input_domain(
        self,
        similarity: SimilarityAgentOutput,
        intelligence: DomainIntelligenceAgentOutput,
        content: WebsiteContentAgentOutput,
        safe_browsing: SafeBrowsingAgentOutput,
    ) -> str:
        """
        Best-effort resolution of the input domain from available agent outputs.
        Falls back to an empty string if none are provided.
        """
        for source in (similarity, intelligence, content, safe_browsing):
            domain = source.get("input_domain") if isinstance(source, dict) else None
            if isinstance(domain, str) and domain:
                return domain
        return ""

    def _compute_final_risk(
        self, similarity_risk: float, intelligence_risk: float, content_risk: float, sb_risk: float
    ) -> float:
        """
        Compute weighted final risk score using the specified weights.
        """
        score = (
            similarity_risk * self.SIMILARITY_WEIGHT
            + intelligence_risk * self.INTELLIGENCE_WEIGHT
            + content_risk * self.CONTENT_WEIGHT
            + sb_risk * self.SAFE_BROWSING_WEIGHT
        )
        # Clamp to [0, 1] for safety
        return max(0.0, min(1.0, score))

    def _classify(self, final_risk_score: float) -> ClassificationLabel:
        """
        Map final risk score to a discrete label.
        Modified threshold: Even a low risk score (> 0.0) triggers at least a SUSPICIOUS label,
        while > 0.5 triggers PHISHING.
        """
        if final_risk_score > 0.5:
            return "PHISHING"
        if final_risk_score > 0.0:
            return "SUSPICIOUS"
        return "SAFE"

    def _confidence_for_classification(
        self, classification: ClassificationLabel
    ) -> ConfidenceLabel:
        """
        Map classification label to confidence level, per RSC specification.
        """
        if classification == "PHISHING":
            return "HIGH"
        if classification == "SUSPICIOUS":
            return "MEDIUM"
        return "LOW"

    def _build_explanation(
        self,
        similarity: SimilarityAgentOutput,
        intelligence: DomainIntelligenceAgentOutput,
        content: WebsiteContentAgentOutput,
        safe_browsing: SafeBrowsingAgentOutput,
        final_risk_score: float,
        classification: ClassificationLabel,
    ) -> List[str]:
        """
        Build a human-readable explanation of the decision.
        """
        signals: List[str] = []

        # Always describe the overall outcome first
        signals.append(
            f"Final risk score {final_risk_score:.2f} classified as {classification}."
        )

        if not safe_browsing.get("is_safe", True):
            signals.append("Google Safe Browsing flagged this URL as malicious!")

        # Similarity-based explanations
        brand = similarity.get("brand_detected")
        similarity_score = similarity.get("similarity_score")
        if brand and similarity_score is not None and similarity_score >= 0.7:
            signals.append(
                f"Domain resembles known brand '{brand}' with similarity score {similarity_score:.2f}."
            )
        elif similarity_score is not None and similarity_score >= 0.7:
            signals.append(
                f"Domain is highly similar to a known domain (similarity score {similarity_score:.2f})."
            )

        # Domain intelligence explanations
        domain_age_days = intelligence.get("domain_age_days")
        if intelligence.get("is_new_domain"):
            if domain_age_days is not None:
                signals.append(
                    f"Domain registered recently ({domain_age_days} days old)."
                )
            else:
                signals.append("Domain flagged as newly registered.")

        if intelligence.get("whois_privacy_enabled"):
            signals.append("WHOIS privacy is enabled, hiding registrant information.")

        if not intelligence.get("has_mx_record", True):
            signals.append("Domain has no MX (mail) records, unusual for legitimate domains.")

        nameserver_count = intelligence.get("nameserver_count")
        if isinstance(nameserver_count, int) and nameserver_count < 2:
            signals.append(
                f"Low nameserver redundancy detected (nameserver_count={nameserver_count})."
            )

        # Website content explanations
        if not content.get("page_reachable", True):
            signals.append("Website is not reachable.")

        if content.get("login_form_detected") or content.get("password_field_detected"):
            signals.append("Login or password input form detected on the page.")

        suspicious_keywords = content.get("suspicious_keywords_found") or []
        if suspicious_keywords:
            sample = ", ".join(suspicious_keywords[:5])
            signals.append(f"Suspicious phishing-related keywords present: {sample}.")

        external_scripts_count = content.get("external_scripts_count")
        if isinstance(external_scripts_count, int) and external_scripts_count > 10:
            signals.append(
                f"High number of external scripts detected ({external_scripts_count})."
            )

        forms_count = content.get("forms_count")
        if isinstance(forms_count, int) and forms_count > 3:
            signals.append(f"Multiple forms detected on the page ({forms_count}).")

        # If no specific signals were collected, still provide a minimum explanation.
        if len(signals) == 1:
            signals.append(
                "No strong individual red flags detected; classification is based on combined agent risk scores."
            )

        return signals


__all__ = [
    "SimilarityAgentOutput",
    "DomainIntelligenceAgentOutput",
    "WebsiteContentAgentOutput",
    "SafeBrowsingAgentOutput",
    "DecisionAgentResult",
    "DecisionAgent",
]
