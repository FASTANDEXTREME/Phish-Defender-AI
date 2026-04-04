"""
Cross-Reference Engine — correlates signals across agents to detect
brand impersonation patterns that no single agent can identify alone.

This module implements Section 8 of the Audit Report:
- Brand detected in page content vs. actual domain
- Brand detected in domain name vs. hosting platform
- Payment/credential collection on impersonation pages
- Scam indicators on disposable domains

Runs AFTER all analysis agents complete but BEFORE the Decision Agent.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from core.config import (
    CRE_BRAND_CONTENT_MISMATCH_RISK,
    CRE_BRAND_DOMAIN_MISMATCH_RISK,
    CRE_HOSTED_BRAND_IMPERSONATION_RISK,
    CRE_BRAND_PLUS_CREDENTIAL_RISK,
    CRE_PAYMENT_ON_DISPOSABLE_RISK,
    CRE_SCAM_ON_DISPOSABLE_RISK,
)

logger = logging.getLogger(__name__)


class CrossReferenceEngine:
    """
    Runs after all analysis agents complete. Receives their outputs and
    computes cross-agent correlation signals that no individual agent
    can produce on its own.

    Input: outputs from Similarity, Intelligence, and Content agents.
    Output: a CrossReferenceOutput dict with correlation signals + risk score.
    """

    def run(
        self,
        similarity: Dict[str, Any],
        intelligence: Dict[str, Any],
        content: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Correlate signals across agents and produce a cross-reference risk score.

        Returns a dict matching the CrossReferenceOutput TypedDict contract.
        """
        # ---- Extract key signals from each agent ----
        content_brands: List[str] = content.get("brand_impersonation_brands", []) or []
        domain_brand: str | None = similarity.get("brand_name") or similarity.get("brand_detected")
        is_hosted: bool = bool(intelligence.get("is_hosted_platform", False))
        is_new: bool = bool(intelligence.get("is_new_domain", False))
        has_login: bool = bool(content.get("login_form_detected") or content.get("password_field_detected"))
        has_payment: bool = bool(content.get("payment_form_detected", False))
        scam_count: int = len(content.get("scam_indicators_found", []) or [])

        # ---- Cross-reference checks ----
        brand_content_mismatch: bool = len(content_brands) > 0
        brand_domain_mismatch: bool = bool(domain_brand) and is_hosted
        hosted_brand_impersonation: bool = brand_content_mismatch and brand_domain_mismatch

        # ---- Composite risk score ----
        risk: float = 0.0

        # Tier 1: Full impersonation (all 3 signals align)
        if hosted_brand_impersonation:
            risk = max(risk, CRE_HOSTED_BRAND_IMPERSONATION_RISK)
            logger.warning(
                "CRE: Hosted brand impersonation detected "
                "(content brands: %s, domain brand: %s, hosted: True)",
                content_brands, domain_brand,
            )
        elif brand_content_mismatch:
            # Tier 2: Brand in page content but domain is wrong
            risk = max(risk, CRE_BRAND_CONTENT_MISMATCH_RISK)
            logger.warning("CRE: Brand-content mismatch detected (brands: %s)", content_brands)
        elif brand_domain_mismatch:
            # Tier 3: Brand in domain name but on hosted platform
            risk = max(risk, CRE_BRAND_DOMAIN_MISMATCH_RISK)
            logger.info("CRE: Brand-domain mismatch (brand: %s on hosted platform)", domain_brand)

        # Additive checks: credential/payment collection on impersonation
        if brand_content_mismatch and (has_login or has_payment):
            risk = max(risk, CRE_BRAND_PLUS_CREDENTIAL_RISK)
            logger.warning("CRE: Brand impersonation + credential/payment collection detected")

        # Payment form on disposable (new or hosted) domain
        if has_payment and (is_new or is_hosted):
            risk = max(risk, CRE_PAYMENT_ON_DISPOSABLE_RISK)
            logger.warning("CRE: Payment form on new/hosted domain")

        # Scam indicators on disposable domain
        if scam_count >= 2 and (is_new or is_hosted):
            risk = max(risk, CRE_SCAM_ON_DISPOSABLE_RISK)
            logger.warning("CRE: Scam indicators (%d) on new/hosted domain", scam_count)

        risk = max(0.0, min(1.0, risk))

        return {
            "brand_content_mismatch": brand_content_mismatch,
            "brand_domain_mismatch": brand_domain_mismatch,
            "hosted_brand_impersonation": hosted_brand_impersonation,
            "content_brand_names": content_brands,
            "domain_brand_name": domain_brand,
            "cross_ref_risk_score": round(risk, 4),
        }


__all__ = ["CrossReferenceEngine"]
