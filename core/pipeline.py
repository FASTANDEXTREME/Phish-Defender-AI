import argparse
import json
from typing import Any, Dict

from agents.decision_agent import DecisionAgent
from agents.domain_intelligence_agent import DomainIntelligenceAgent
from agents.domain_similarity_agent import DomainSimilarityAgent
from agents.website_content_agent import WebsiteContentAgent
from agents.safe_browsing_agent import SafeBrowsingAgent
from core.user_input_domain import UserInputDomainModule


def run_pipeline(domain: str) -> Dict[str, Any]:
    """
    End-to-end pipeline:
    - User Input Domain Module (cleaning)
    - Domain Similarity Agent
    - Domain Intelligence Agent
    - Website Content Analysis Agent
    - Risk Score & Classification (Decision Agent)
    """
    # 1) Clean and validate the user-provided domain/URL.
    uid_module = UserInputDomainModule()
    cleaned = uid_module.clean(domain)
    clean_domain = cleaned.clean_domain
    full_url = cleaned.original_input

    # 2) Initialize agents.
    similarity_agent = DomainSimilarityAgent()
    intelligence_agent = DomainIntelligenceAgent()
    content_agent = WebsiteContentAgent()
    safe_browsing_agent = SafeBrowsingAgent()
    decision_agent = DecisionAgent()

    # 3) Run all analysis agents concurrently on the cleaned domain.
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_similarity = executor.submit(similarity_agent.run, clean_domain)
        future_intelligence = executor.submit(intelligence_agent.run, clean_domain)
        future_content = executor.submit(content_agent.run, full_url)
        future_sb = executor.submit(safe_browsing_agent.run, full_url)

        similarity_output = future_similarity.result().to_dict()
        intelligence_output = future_intelligence.result().to_dict()
        content_output = future_content.result().to_dict()
        sb_output = future_sb.result().to_dict()

    result = decision_agent.run(
        similarity=similarity_output,
        intelligence=intelligence_output,
        content=content_output,
        safe_browsing=sb_output,
    )

    return result.to_dict()


def main() -> None:
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
        # User-friendly error message for invalid input.
        print(f"Input error: {exc}")
        return

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()

