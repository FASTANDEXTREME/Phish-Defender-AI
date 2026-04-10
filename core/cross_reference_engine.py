"""
Cross-Reference Engine — correlates signals across agents to detect
brand impersonation patterns that no single agent can identify alone.

This module implements Section 8 of the Audit Report:
- Brand detected in page content vs. actual domain
- Brand detected in domain name vs. hosting platform
- Payment/credential collection on impersonation pages
- Scam indicators on disposable domains

Runs AFTER all analysis agents complete but BEFORE the Decision Agent.

FP-Fix: Added domain alias awareness, tiered scoring, and established
domain trust to prevent false positives on legitimate sites.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from core.config import (
    CRE_BRAND_CONTENT_MISMATCH_RISK,
    CRE_BRAND_STRONG_MISMATCH_RISK,
    CRE_BRAND_DOMAIN_MISMATCH_RISK,
    CRE_HOSTED_BRAND_IMPERSONATION_RISK,
    CRE_BRAND_PLUS_CREDENTIAL_RISK,
    CRE_PAYMENT_ON_DISPOSABLE_RISK,
    CRE_SCAM_ON_DISPOSABLE_RISK,
    BRAND_DOMAIN_ALIASES,
    KNOWN_BRANDS,
)

logger = logging.getLogger(__name__)


def _is_domain_in_brand_family(domain: str, brand_name: str) -> bool:
    """
    Check if a domain belongs to the same organization as the given brand.
    Used to prevent false positives: bing.com mentioning 'microsoft' is not impersonation.
    """
    import tldextract
    ext = tldextract.extract(domain)
    domain_root = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    
    # Get the brand's canonical domain
    brand_canonical = KNOWN_BRANDS.get(brand_name, "")
    if not brand_canonical:
        return False
    
    bc_ext = tldextract.extract(brand_canonical)
    brand_root = f"{bc_ext.domain}.{bc_ext.suffix}" if bc_ext.suffix else bc_ext.domain
    
    # Direct match
    if domain_root == brand_root:
        return True
    
    # Check alias tables — is the domain an alias of the brand's parent?
    for canonical, aliases in BRAND_DOMAIN_ALIASES.items():
        canon_ext = tldextract.extract(canonical)
        canon_root = f"{canon_ext.domain}.{canon_ext.suffix}" if canon_ext.suffix else canon_ext.domain
        
        # Build the set of all domains in this family
        family_roots = {canon_root}
        for alias in aliases:
            a_ext = tldextract.extract(alias)
            family_roots.add(f"{a_ext.domain}.{a_ext.suffix}" if a_ext.suffix else a_ext.domain)
        
        # If the domain is in this family AND the brand's canonical domain is also in this family
        if domain_root in family_roots and brand_root in family_roots:
            return True
    
    return False


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
        ssl_valid: bool = bool(intelligence.get("ssl_valid", False))
        domain_age: int | None = intelligence.get("domain_age_days")
        
        # ---- Domain alias filtering ----
        # Filter out brand mentions that belong to the same organization as the page domain
        final_domain = content.get("final_domain", "") or content.get("input_domain", "")
        filtered_brands: List[str] = []
        for brand in content_brands:
            if not _is_domain_in_brand_family(final_domain, brand):
                filtered_brands.append(brand)
        
        # Use filtered brands for all CRE checks
        content_brands = filtered_brands

        # ---- Cross-reference checks ----
        brand_content_mismatch: bool = len(content_brands) > 0
        brand_domain_mismatch: bool = bool(domain_brand) and is_hosted
        hosted_brand_impersonation: bool = brand_content_mismatch and brand_domain_mismatch

        # ---- Established domain trust ----
        # Domains older than 2 years with valid SSL are much less likely to be phishing
        is_established = (
            domain_age is not None 
            and domain_age > 730  # > 2 years old
            and ssl_valid
        )

        # ---- Composite risk score ----
        risk: float = 0.0

        # Tier 1: Full impersonation (all 3 signals align)
        if hosted_brand_impersonation:
            # But NOT if the domain is established — reduces false positives on
            # legitimate hosted platforms (amazonaws.com → aws.amazon.com)
            if is_established:
                risk = max(risk, CRE_BRAND_CONTENT_MISMATCH_RISK)
                logger.warning(
                    "CRE: Hosted brand impersonation detected but domain is established "
                    "(content brands: %s, domain brand: %s, hosted: True, age: %s days)",
                    content_brands, domain_brand, domain_age,
                )
            else:
                risk = max(risk, CRE_HOSTED_BRAND_IMPERSONATION_RISK)
                logger.warning(
                    "CRE: Hosted brand impersonation detected "
                    "(content brands: %s, domain brand: %s, hosted: True)",
                    content_brands, domain_brand,
                )
        elif brand_content_mismatch:
            # Tier 2: Brand in page content but domain is wrong
            # Use tiered scoring: body-text mentions get lower risk
            risk = max(risk, CRE_BRAND_CONTENT_MISMATCH_RISK)
            logger.warning("CRE: Brand-content mismatch detected (brands: %s)", content_brands)
        elif brand_domain_mismatch:
            # Tier 3: Brand in domain name but on hosted platform
            risk = max(risk, CRE_BRAND_DOMAIN_MISMATCH_RISK)
            logger.info("CRE: Brand-domain mismatch (brand: %s on hosted platform)", domain_brand)

        # Additive checks: credential/payment collection on impersonation
        if brand_content_mismatch and (has_login or has_payment):
            if is_new or is_hosted or not ssl_valid:
                risk = max(risk, CRE_BRAND_PLUS_CREDENTIAL_RISK)
                logger.warning("CRE: Brand impersonation + credential/payment collection detected on an untrusted domain")
            elif is_established:
                # Established domain with brand mention + login = likely legitimate
                # (e.g. github.com has login forms and mentions other brands)
                logger.info("CRE: Brand impersonation + credential/payment on established domain — suppressing risk boost")
                # Don't increase risk further
            else:
                risk = max(risk, CRE_BRAND_CONTENT_MISMATCH_RISK)
                logger.warning("CRE: Brand impersonation + credential/payment collection detected, but domain appears established (graceful degradation)")

        # Payment form on disposable (new or hosted) domain
        if has_payment and (is_new or is_hosted):
            risk = max(risk, CRE_PAYMENT_ON_DISPOSABLE_RISK)
            logger.warning("CRE: Payment form on new/hosted domain")

        # Scam indicators on disposable domain
        if scam_count >= 2 and (is_new or is_hosted):
            risk = max(risk, CRE_SCAM_ON_DISPOSABLE_RISK)
            logger.warning("CRE: Scam indicators (%d) on new/hosted domain", scam_count)

        # ---- Established domain trust discount ----
        # For established domains, apply a significant risk reduction
        # This prevents well-known sites from crossing PHISHING thresholds
        if is_established and risk > 0 and not (is_new or is_hosted):
            discount = 0.15
            old_risk = risk
            risk = max(0.0, risk - discount)
            logger.info(
                "CRE: Established domain trust discount: %.2f → %.2f (age: %s days, SSL: %s)",
                old_risk, risk, domain_age, ssl_valid,
            )

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

