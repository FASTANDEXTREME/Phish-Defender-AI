"""
Pipeline — orchestrates the end-to-end phishing domain detection workflow.

Timeout enforcement strategy:
- Uses threading.Event (not concurrent.futures timeout) as the timeout
  primitive. Event.wait(timeout) is the most reliable cross-platform
  timeout mechanism in CPython — it does not depend on GIL scheduling,
  thread pool internals, or nested executor behavior.
- Each agent runs in a daemon thread. If it doesn't complete by the
  deadline, the pipeline proceeds with safe defaults and marks the
  agent as 'degraded'.
- A pipeline watchdog timer logs CRITICAL if total time exceeds deadline+5s.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional

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

# ---------------------------------------------------------------------------
# Global pipeline deadline — hard cap on total wall-clock time
# ---------------------------------------------------------------------------
PIPELINE_DEADLINE_S = 30.0  # seconds — absolute maximum for the entire pipeline
AGENT_HARD_TIMEOUT_S = 7.0  # seconds — per-agent hard ceiling


# ---------------------------------------------------------------------------
# Agent runner using threading.Event (not concurrent.futures)
# ---------------------------------------------------------------------------
class _AgentTask:
    """
    Runs an agent method in a daemon thread and provides a reliable
    timeout via threading.Event.wait().

    Unlike concurrent.futures.Future.result(timeout), Event.wait(timeout)
    is a simple timedwait on a kernel-level synchronization primitive,
    immune to GIL scheduling issues and nested executor deadlocks.
    """

    __slots__ = ("_event", "_result", "_elapsed_ms", "_error", "_agent_name")

    def __init__(self, agent, method_name: str, arg: str, agent_name: str):
        self._event = threading.Event()
        self._result: Optional[Dict] = None
        self._elapsed_ms: float = 0.0
        self._error: Optional[str] = None
        self._agent_name = agent_name

        thread = threading.Thread(
            target=self._run, args=(agent, method_name, arg),
            daemon=True, name=f"Agent-{agent_name}",
        )
        thread.start()

    def _run(self, agent, method_name: str, arg: str) -> None:
        start = time.monotonic()
        try:
            result = getattr(agent, method_name)(arg)
            self._elapsed_ms = (time.monotonic() - start) * 1000
            self._result = result.to_dict()
        except Exception as exc:
            self._elapsed_ms = (time.monotonic() - start) * 1000
            self._error = str(exc)
            logger.exception("Agent %s failed for %s", self._agent_name, arg)
        finally:
            self._event.set()

    def wait(self, timeout: float) -> bool:
        """Wait for the agent to complete. Returns True if done, False if timed out."""
        return self._event.wait(timeout=timeout)

    @property
    def is_done(self) -> bool:
        return self._event.is_set()

    def get_result(self, default: Dict[str, Any]) -> tuple[Dict, float, Optional[str]]:
        """
        Return (result_dict, elapsed_ms, error_string).
        If the agent hasn't completed, returns the default.
        """
        if self._event.is_set():
            if self._error:
                return default, self._elapsed_ms, self._error
            return (self._result or default), self._elapsed_ms, None
        # Not done — timed out
        return default, self._elapsed_ms, f"Hard timeout ({AGENT_HARD_TIMEOUT_S}s exceeded)"


# ---------------------------------------------------------------------------
# Default safe outputs for when an agent fails
# ---------------------------------------------------------------------------
_DEFAULT_SIMILARITY: Dict[str, Any] = {"risk_score": 0.0, "similarity_score": 0.0, "brand_detected": None}
_DEFAULT_INTELLIGENCE: Dict[str, Any] = {"risk_score": 0.0, "is_new_domain": False, "has_mx_record": True, "ssl_valid": False}
_DEFAULT_CONTENT: Dict[str, Any] = {"risk_score": 0.0, "page_reachable": False, "legitimate_app_behavior": False}
_DEFAULT_SAFE_BROWSING: Dict[str, Any] = {"risk_score": 0.0, "is_safe": True, "threat_matches": [], "is_disabled": False}
_DEFAULT_PHISHTANK: Dict[str, Any] = {"risk_score": 0.0, "is_phishing": False, "is_disabled": False}


def _remaining(deadline: float) -> float:
    """Return seconds remaining until the pipeline deadline, floored at 0."""
    return max(0.0, deadline - time.monotonic())


def run_pipeline(domain: str, safebrowsing_enabled: bool = True, phishtank_enabled: bool = True) -> Dict[str, Any]:
    """
    End-to-end pipeline with global deadline enforcement.

    Uses threading.Event for timeouts — the most reliable primitive
    available in CPython, immune to concurrent.futures quirks.
    """
    pipeline_start = time.monotonic()
    pipeline_deadline = pipeline_start + PIPELINE_DEADLINE_S

    # Track degraded agents for frontend visibility
    agent_errors: Dict[str, str] = {}
    degraded_agents: List[str] = []

    # WATCHDOG: Log critical alert if pipeline vastly exceeds deadline
    def _deadline_watchdog():
        elapsed = (time.monotonic() - pipeline_start) * 1000
        if elapsed > (PIPELINE_DEADLINE_S + 5) * 1000:
            logger.critical(
                "PIPELINE WATCHDOG: %s exceeded hard deadline by %.1fms!",
                domain, elapsed - PIPELINE_DEADLINE_S * 1000,
            )

    watchdog = threading.Timer(PIPELINE_DEADLINE_S + 5, _deadline_watchdog)
    watchdog.daemon = True
    watchdog.start()

    try:
        return _run_pipeline_inner(
            domain, safebrowsing_enabled, phishtank_enabled,
            pipeline_start, pipeline_deadline, agent_errors, degraded_agents,
        )
    finally:
        watchdog.cancel()


def _run_pipeline_inner(
    domain: str,
    safebrowsing_enabled: bool,
    phishtank_enabled: bool,
    pipeline_start: float,
    pipeline_deadline: float,
    agent_errors: Dict[str, str],
    degraded_agents: List[str],
) -> Dict[str, Any]:
    """Inner pipeline logic, separated for clean watchdog try/finally."""

    # 1) Clean and validate
    cleaned = _uid_module.clean(domain)
    clean_domain = cleaned.clean_domain
    full_url = cleaned.original_input

    # ---------------------------------------------------------------
    # 2) Launch all fast agents as daemon threads (non-blocking)
    # ---------------------------------------------------------------
    task_sim = _AgentTask(_similarity_agent, "run", clean_domain, "similarity")
    task_intel = _AgentTask(_intelligence_agent, "run", clean_domain, "intelligence")
    task_sb = _AgentTask(_safe_browsing_agent, "run", full_url, "safe_browsing") if safebrowsing_enabled else None
    task_pt = _AgentTask(_phishtank_agent, "run", full_url, "phishtank") if phishtank_enabled else None

    all_tasks = [
        ("similarity", task_sim),
        ("intelligence", task_intel),
    ]
    if task_sb:
        all_tasks.append(("safe_browsing", task_sb))
    if task_pt:
        all_tasks.append(("phishtank", task_pt))

    # ---------------------------------------------------------------
    # 3) Wait for all fast agents — uses Event.wait() with per-agent
    #    timeout capped by both AGENT_HARD_TIMEOUT_S and pipeline deadline
    # ---------------------------------------------------------------
    for name, task in all_tasks:
        remaining = _remaining(pipeline_deadline)
        timeout = min(AGENT_HARD_TIMEOUT_S, remaining)
        timeout = max(0.1, timeout)  # Floor at 100ms
        done = task.wait(timeout=timeout)
        if not done:
            logger.error(
                "Agent %s HARD TIMEOUT (%.1fs limit, %.1fs remaining in pipeline)",
                name, AGENT_HARD_TIMEOUT_S, _remaining(pipeline_deadline),
            )

    # ---------------------------------------------------------------
    # 4) Collect results — use defaults for anything that didn't finish
    # ---------------------------------------------------------------
    def _collect(name: str, task: Optional[_AgentTask], default: Dict) -> tuple[Dict, float, Optional[str]]:
        if task is None:
            return default, 0.0, None
        result, elapsed, err = task.get_result(default)
        if err or result.get("is_disabled") or result.get("is_error"):
            if err:
                agent_errors[name] = err
            if name not in degraded_agents:
                degraded_agents.append(name)
        return result, elapsed, err

    sim_result, sim_time, sim_err = _collect("similarity", task_sim, _DEFAULT_SIMILARITY)
    intel_result, intel_time, intel_err = _collect("intelligence", task_intel, _DEFAULT_INTELLIGENCE)

    if safebrowsing_enabled:
        sb_result, sb_time, sb_err = _collect("safe_browsing", task_sb, _DEFAULT_SAFE_BROWSING)
    else:
        sb_result, sb_time, sb_err = {"risk_score": 0.0, "is_safe": True, "threat_matches": [], "is_disabled": True}, 0.0, None

    if phishtank_enabled:
        pt_result, pt_time, pt_err = _collect("phishtank", task_pt, _DEFAULT_PHISHTANK)
    else:
        pt_result, pt_time, pt_err = {"risk_score": 0.0, "is_phishing": False, "is_disabled": True}, 0.0, None

    # ---------------------------------------------------------------
    # 5) Content agent — with deadline-aware timeout
    # ---------------------------------------------------------------
    remaining = _remaining(pipeline_deadline)
    content_skip_threshold = max(2.0, PIPELINE_DEADLINE_S * 0.40)  # Skip if <40% left

    if remaining < content_skip_threshold:
        logger.warning(
            "Pipeline deadline imminent (%.1fs left, threshold=%.1fs) — skipping content agent",
            remaining, content_skip_threshold,
        )
        content_result = _DEFAULT_CONTENT.copy()
        content_time = 0.0
        content_err = "Skipped — pipeline deadline"
        agent_errors["content"] = content_err
        degraded_agents.append("content")
    else:
        # EARLY EXIT STRATEGY: Skip heavy rendering if domain confirmed malicious
        is_known_phishing = False
        if safebrowsing_enabled or phishtank_enabled:
            is_known_phishing = (
                sb_result.get("risk_score", 0.0) >= 0.9
                or pt_result.get("risk_score", 0.0) >= 0.9
            )

        if is_known_phishing:
            logger.info(
                "Early exit triggered: domain %s is confirmed malicious. Skipping heavy JS rendering.",
                clean_domain,
            )
            content_result = _DEFAULT_CONTENT.copy()
            content_result["page_reachable"] = False
            content_result["risk_score"] = 1.0
            content_time = 0.0
            content_err = "Skipped due to early exit"
        else:
            # Run content agent with remaining budget
            content_timeout = min(15.0, remaining - 2.0)  # Reserve 2s for decision
            content_timeout = max(3.0, content_timeout)

            task_content = _AgentTask(_content_agent, "run", full_url, "content")
            done = task_content.wait(timeout=content_timeout)
            if not done:
                logger.error("Content agent HARD TIMEOUT (%.1fs)", content_timeout)
            content_result, content_time, content_err = task_content.get_result(_DEFAULT_CONTENT)
            if content_err:
                agent_errors["content"] = content_err
                degraded_agents.append("content")

    # ---------------------------------------------------------------
    # 6) Collect timings
    # ---------------------------------------------------------------
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
        if err and name not in agent_errors:
            agent_errors[name] = err
        outputs[name] = result or default

    # ---------------------------------------------------------------
    # 7) Cross-Reference Engine
    # ---------------------------------------------------------------
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

    # ---------------------------------------------------------------
    # 8) Decision Agent
    # ---------------------------------------------------------------
    result = _decision_agent.run(
        similarity=outputs["similarity"],
        intelligence=outputs["intelligence"],
        content=outputs["content"],
        safe_browsing=outputs["safe_browsing"],
        phishtank=outputs["phishtank"],
        cross_reference=cross_ref_result,
    )

    output = result.to_dict()

    # ---------------------------------------------------------------
    # 9) Enrich with pipeline metadata + degradation info
    # ---------------------------------------------------------------
    total_time = (time.monotonic() - pipeline_start) * 1000
    degraded_agents_unique = list(dict.fromkeys(degraded_agents))

    output["pipeline_metadata"] = {
        "total_ms": round(total_time, 1),
        "agent_timings": agent_timings,
    }
    if agent_errors:
        output["pipeline_metadata"]["agent_errors"] = agent_errors
    if degraded_agents_unique:
        output["pipeline_metadata"]["degraded_agents"] = degraded_agents_unique
        output["pipeline_metadata"]["results_degraded"] = True
    else:
        output["pipeline_metadata"]["results_degraded"] = False

    if total_time > PIPELINE_DEADLINE_S * 1000:
        logger.warning(
            "Pipeline for %s exceeded deadline: %.1fms (limit: %.0fms)",
            clean_domain, total_time, PIPELINE_DEADLINE_S * 1000,
        )

    return output


def main() -> None:
    import argparse

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
