import os
import requests
from dataclasses import dataclass
from dotenv import load_dotenv
from typing import Dict, Any, List

load_dotenv()

@dataclass(frozen=True)
class SafeBrowsingResult:
    input_domain: str
    is_safe: bool
    threat_matches: List[Dict[str, Any]]
    risk_score: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_domain": self.input_domain,
            "is_safe": self.is_safe,
            "threat_matches": self.threat_matches,
            "risk_score": self.risk_score,
        }

class SafeBrowsingAgent:
    """
    Agent that uses Google Safe Browsing API to detect known malicious URLs.
    Expects GOOGLE_SAFE_BROWSING_API_KEY as an environment variable, 
    or passed into the constructor.
    """
    
    # We can default to the provided key for testing, but in production this should be an env var
    DEFAULT_API_KEY = os.getenv("API_KEY")
    ENDPOINT_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={}"

    def __init__(self, api_key: str = None, timeout: float = 5.0):
        self._api_key = api_key or os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", self.DEFAULT_API_KEY)
        self._timeout = timeout

    def run(self, url: str) -> SafeBrowsingResult:
        """
        Check the URL against Google Safe Browsing.
        """
        # Ensure we check the full URL or a scheme-prefixed version if it's just a domain
        check_url = url if url.startswith("http") else f"http://{url}"

        payload = {
            "client": {
                "clientId": "phish-defender-ai",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": check_url}
                ]
            }
        }

        try:
            endpoint = self.ENDPOINT_URL.format(self._api_key)
            response = requests.post(endpoint, json=payload, timeout=self._timeout)
            response.raise_for_status()
            
            result = response.json()
            matches = result.get("matches", [])
            
            is_safe = len(matches) == 0
            
            # If Google Safe Browsing flags it, the risk is extremely high (1.0)
            risk_score = 0.0 if is_safe else 1.0
            
            return SafeBrowsingResult(
                input_domain=url,
                is_safe=is_safe,
                threat_matches=matches,
                risk_score=risk_score
            )
            
        except Exception as e:
            # If the API fails, we fail open (assume safe) but log it in a real app
            return SafeBrowsingResult(
                input_domain=url,
                is_safe=True,
                threat_matches=[],
                risk_score=0.0
            )

__all__ = ["SafeBrowsingAgent", "SafeBrowsingResult"]
