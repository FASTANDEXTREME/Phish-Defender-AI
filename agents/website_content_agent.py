from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

import requests
from bs4 import BeautifulSoup

from agents.decision_agent import WebsiteContentAgentOutput


SUSPICIOUS_KEYWORDS: List[str] = [
    "verify your account",
    "confirm your account",
    "update payment",
    "login immediately",
    "security alert",
    "suspended account",
    "verify identity",
    "account locked",
    "confirm password",
    "unusual activity",
]


@dataclass(frozen=True)
class WebsiteContentResult:
    input_domain: str
    page_reachable: bool
    login_form_detected: bool
    password_field_detected: bool
    suspicious_keywords_found: List[str]
    external_scripts_count: int
    forms_count: int
    risk_score: float

    def to_dict(self) -> WebsiteContentAgentOutput:
        return {
            "input_domain": self.input_domain,
            "page_reachable": self.page_reachable,
            "login_form_detected": self.login_form_detected,
            "password_field_detected": self.password_field_detected,
            "suspicious_keywords_found": self.suspicious_keywords_found,
            "external_scripts_count": self.external_scripts_count,
            "forms_count": self.forms_count,
            "risk_score": self.risk_score,
        }


class WebsiteContentAgent:
    """
    Website Content Analysis Agent.

    Downloads HTML content, parses it, and extracts phishing-related signals.
    """

    def __init__(self, timeout: float = 5.0) -> None:
        self._timeout = timeout

    def run(self, domain: str) -> WebsiteContentResult:
        input_domain = domain.strip().lower()

        html = self._fetch_html(input_domain)
        if html is None:
            # Page unreachable: return minimal, low-risk output.
            return WebsiteContentResult(
                input_domain=input_domain,
                page_reachable=False,
                login_form_detected=False,
                password_field_detected=False,
                suspicious_keywords_found=[],
                external_scripts_count=0,
                forms_count=0,
                risk_score=0.0,
            )

        soup = BeautifulSoup(html, "lxml")

        forms = soup.find_all("form")
        forms_count = len(forms)

        password_inputs = soup.find_all("input", {"type": "password"})
        password_field_detected = len(password_inputs) > 0

        login_form_detected = any(
            form.find("input", {"type": "password"}) is not None for form in forms
        )

        text = soup.get_text(separator=" ").lower()
        suspicious_found: List[str] = [
            keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in text
        ]

        scripts = soup.find_all("script")
        external_scripts_count = 0
        for script in scripts:
            src = script.get("src")
            if not src:
                continue
            # Treat any absolute URL as external for simplicity.
            if src.startswith("http://") or src.startswith("https://") or src.startswith("//"):
                external_scripts_count += 1

        risk_score = self._compute_risk_score(
            login_form_detected=login_form_detected,
            password_field_detected=password_field_detected,
            suspicious_keywords_found=suspicious_found,
            external_scripts_count=external_scripts_count,
            forms_count=forms_count,
        )

        return WebsiteContentResult(
            input_domain=input_domain,
            page_reachable=True,
            login_form_detected=login_form_detected,
            password_field_detected=password_field_detected,
            suspicious_keywords_found=suspicious_found,
            external_scripts_count=external_scripts_count,
            forms_count=forms_count,
            risk_score=risk_score,
        )

    def _fetch_html(self, target: str) -> Optional[str]:
        """
        Try HTTPS first, then HTTP. Handle network errors gracefully.
        Using a standard User-Agent to avoid basic anti-bot blocks.
        """
        if target.startswith("http://") or target.startswith("https://"):
            urls = [target]
        else:
            urls = [f"https://{target}", f"http://{target}"]
            
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        
        import warnings
        from urllib3.exceptions import InsecureRequestWarning
        warnings.simplefilter('ignore', InsecureRequestWarning)

        for url in urls:
            try:
                # Use a longer timeout and disable SSL verification to handle slow/misconfigured sites
                resp = requests.get(url, headers=headers, timeout=15.0, verify=False)
                if resp.status_code >= 200 and resp.status_code < 400:
                    return resp.text
            except Exception:
                continue
        return None

    def _compute_risk_score(
        self,
        login_form_detected: bool,
        password_field_detected: bool,
        suspicious_keywords_found: List[str],
        external_scripts_count: int,
        forms_count: int,
    ) -> float:
        risk = 0.0

        if login_form_detected:
            risk += 0.3

        if password_field_detected:
            risk += 0.2

        if suspicious_keywords_found:
            risk += 0.1

        if external_scripts_count > 5:
            risk += 0.1

        if forms_count > 1:
            risk += 0.1

        # Maximum possible risk is 0.8 according to the spec.
        risk = min(risk, 0.8)
        return max(0.0, min(1.0, risk))


__all__ = ["WebsiteContentAgent", "WebsiteContentResult"]

