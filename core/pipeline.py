"""
Pipeline — orchestrates the end-to-end phishing domain detection workflow.

Improvements over MVP:
- Singleton agent instances (created once, reused across requests)
- Per-agent error isolation (one agent failing degrades, not crashes)
- Timing metadata included in the response
- Structured error reporting
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import time
from typing import Any, Dict, Optional

from agents.decision_agent import DecisionAgent
from agents.domain_intelligence_agent import DomainIntelligenceAgent
from agents.domain_similarity_agent import DomainSimilarityAgent
from agents.website_content_agent import WebsiteContentAgent
from agents.safe_browsing_agent import SafeBrowsingAgent
from core.cross_reference_engine import CrossReferenceEngine
from agents.phishtank_agent import PhishTankAgent
from core.user_input_domain import UserInputDomainModule

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level singletons (created once, reused for all requests)
# ---------------------------------------------------------------------------
_similarity_agent = DomainSimilarityAgent()
_intelligence_agent = DomainIntelligenceAgent()
_content_agent = WebsiteContentAgent()
_safe_browsing_agent = SafeBrowsingAgent()
_phishtank_agent = PhishTankAgent()
_cross_reference_engine = CrossReferenceEngine()
_decision_agent = DecisionAgent()
_uid_module = UserInputDomainModule()

# Pre-warm tldextract's public suffix list cache at startup so the first
# request doesn't trigger a network download (fails in air-gapped envs).
try:
    import tldextract
    tldextract.extract("warmup.example.com")
    logger.debug("tldextract public suffix list cache warmed up")
except Exception:
    pass


def _safe_run_agent(agent, method_name: str, arg: str) -> tuple[Optional[Dict], float, Optional[str]]:
    """
    Run an agent method safely — returns (result_dict, elapsed_ms, error_message).
    On failure, returns (None, elapsed_ms, error_string) instead of raising.
    """
    start = time.monotonic()
    try:
        result = getattr(agent, method_name)(arg)
        elapsed = (time.monotonic() - start) * 1000
        return result.to_dict(), elapsed, None
    except Exception as exc:
        elapsed = (time.monotonic() - start) * 1000
        logger.exception("Agent %s failed for %s", agent.__class__.__name__, arg)
        return None, elapsed, str(exc)


# Default safe outputs for when an agent fails
_DEFAULT_SIMILARITY: Dict[str, Any] = {"risk_score": 0.0, "similarity_score": 0.0, "brand_detected": None}
_DEFAULT_INTELLIGENCE: Dict[str, Any] = {"risk_score": 0.0, "is_new_domain": False, "has_mx_record": True, "ssl_valid": False}
_DEFAULT_CONTENT: Dict[str, Any] = {"risk_score": 0.0, "page_reachable": False, "legitimate_app_behavior": False}
_DEFAULT_SAFE_BROWSING: Dict[str, Any] = {"risk_score": 0.0, "is_safe": True, "threat_matches": [], "is_disabled": False}
_DEFAULT_PHISHTANK: Dict[str, Any] = {"risk_score": 0.0, "is_phishing": False, "is_disabled": False}


def run_pipeline(domain: str, safebrowsing_enabled: bool = True, phishtank_enabled: bool = True) -> Dict[str, Any]:
    """
    End-to-end pipeline:
    1. Clean and validate domain
    2. Run all analysis agents concurrently with error isolation
    3. Aggregate via Decision Agent
    4. Return result with timing metadata
    """
    pipeline_start = time.monotonic()

    # 1) Clean and validate
    cleaned = _uid_module.clean(domain)
    clean_domain = cleaned.clean_domain
    full_url = cleaned.original_input

    # 2) Run agents concurrently with error isolation
    agent_errors: Dict[str, str] = {}
    agent_timings: Dict[str, float] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_sim = executor.submit(_safe_run_agent, _similarity_agent, "run", clean_domain)
        future_intel = executor.submit(_safe_run_agent, _intelligence_agent, "run", clean_domain)
        future_content = executor.submit(_safe_run_agent, _content_agent, "run", full_url)
        
        if safebrowsing_enabled:
            future_sb = executor.submit(_safe_run_agent, _safe_browsing_agent, "run", full_url)
        if phishtank_enabled:
            future_pt = executor.submit(_safe_run_agent, _phishtank_agent, "run", full_url)

        sim_result, sim_time, sim_err = future_sim.result()
        intel_result, intel_time, intel_err = future_intel.result()
        content_result, content_time, content_err = future_content.result()
        
        if safebrowsing_enabled:
            sb_result, sb_time, sb_err = future_sb.result()
        else:
            sb_result, sb_time, sb_err = {"risk_score": 0.0, "is_safe": True, "threat_matches": [], "is_disabled": True}, 0.0, None

        if phishtank_enabled:
            pt_result, pt_time, pt_err = future_pt.result()
        else:
            pt_result, pt_time, pt_err = {"risk_score": 0.0, "is_phishing": False, "is_disabled": True}, 0.0, None

    # Collect timings and errors in one pass
    _agent_results = [
        ("similarity",    sim_result,     sim_time,     sim_err,     _DEFAULT_SIMILARITY),
        ("intelligence",  intel_result,   intel_time,   intel_err,   _DEFAULT_INTELLIGENCE),
        ("content",       content_result, content_time, content_err, _DEFAULT_CONTENT),
        ("safe_browsing", sb_result,      sb_time,      sb_err,      _DEFAULT_SAFE_BROWSING),
        ("phishtank",     pt_result,      pt_time,      pt_err,      _DEFAULT_PHISHTANK),
    ]

    agent_timings: Dict[str, float] = {}
    outputs: Dict[str, Dict[str, Any]] = {}
    for name, result, elapsed, err, default in _agent_results:
        agent_timings[f"{name}_ms"] = round(elapsed, 1)
        if err:
            agent_errors[name] = err
        outputs[name] = result or default

    # 3) Cross-Reference Engine (correlates signals across agents)
    cre_start = time.monotonic()
    try:
        cross_ref_result = _cross_reference_engine.run(
            similarity=outputs["similarity"],
            intelligence=outputs["intelligence"],
            content=outputs["content"],
        )
    except Exception as exc:
        logger.exception("Cross-Reference Engine failed")
        cross_ref_result = {"cross_ref_risk_score": 0.0, "brand_content_mismatch": False}
        agent_errors["cross_reference"] = str(exc)
    agent_timings["cross_reference_ms"] = round((time.monotonic() - cre_start) * 1000, 1)

    # 4) Decision Agent
    result = _decision_agent.run(
        similarity=outputs["similarity"],
        intelligence=outputs["intelligence"],
        content=outputs["content"],
        safe_browsing=outputs["safe_browsing"],
        phishtank=outputs["phishtank"],
        cross_reference=cross_ref_result,
    )

    output = result.to_dict()

    # 4) Enrich with pipeline metadata
    total_time = (time.monotonic() - pipeline_start) * 1000
    output["pipeline_metadata"] = {
        "total_ms": round(total_time, 1),
        "agent_timings": agent_timings,
    }
    if agent_errors:
        output["pipeline_metadata"]["agent_errors"] = agent_errors

    return output


def main() -> None:
    import argparse  # Lazy import — only needed for CLI usage

    parser = argparse.ArgumentParser(
        description="Run Intelligent Phishing Domain Detection pipeline for a single domain."
    )
    parser.add_argument(
        "domain",
        help="Domain or URL to analyze, e.g. 'example.com' or 'https://www.google.com/login'",
    )
    args = parser.parse_args()

    try:
        output = run_pipeline(args.domain)
    except ValueError as exc:
        print(f"Input error: {exc}")
        return

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
