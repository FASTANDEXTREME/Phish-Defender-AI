from __future__ import annotations

"""
User Input Domain Module for the Intelligent Phishing Domain Detection system.

Accepts user-provided domains or URLs, normalizes them, validates the result,
and returns a clean root domain string for downstream agents.
"""

from dataclasses import dataclass
import re
from urllib.parse import urlparse


_DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


@dataclass(frozen=True)
class CleanDomainResult:
    original_input: str
    clean_domain: str


class UserInputDomainModule:
    """
    Entry-point module responsible for:
    - Accepting user input (domain or full URL)
    - Normalizing to a root domain
    - Validating the domain format
    - Returning a clean domain string for downstream agents
    """

    def clean(self, user_input: str) -> CleanDomainResult:
        raw = user_input.strip()
        if not raw:
            raise ValueError("Input is empty. Please provide a domain or URL.")

        domain = self._extract_root_domain(raw)

        if not _DOMAIN_REGEX.match(domain):
            raise ValueError(
                f"'{user_input}' is not a valid domain. "
                "Examples of valid domains: google.com, amazon.co.uk, login-paypal-security.net."
            )

        return CleanDomainResult(original_input=user_input, clean_domain=domain.lower())

    def _extract_root_domain(self, value: str) -> str:
        """
        Extract a root domain from user input that may be a bare domain or a full URL.
        """
        # If input looks like a URL but without scheme, add http:// to help urlparse.
        to_parse = value
        if "://" not in to_parse and "/" in to_parse:
            to_parse = "http://" + to_parse

        parsed = urlparse(to_parse)

        host = parsed.hostname or ""

        # If urlparse did not give us a hostname, treat the input as a bare domain.
        if not host:
            host = value.split("/")[0]

        # Strip common 'www.' prefix.
        if host.startswith("www."):
            host = host[4:]

        # Drop any trailing dot (e.g. 'example.com.')
        return host.rstrip(".")


__all__ = ["UserInputDomainModule", "CleanDomainResult"]

