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
    original_input: str  # Kept as 'original_input' to avoid downstream rename churn, but represents the normalized URL
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

        normalized_url = self._normalize_url(raw)

        return CleanDomainResult(original_input=normalized_url, clean_domain=domain.lower())

    def _normalize_url(self, value: str) -> str:
        """
        Ensure the URL has a scheme. Defaults to http:// if missing.
        Also normalizes trailing slashes for bare domains.
        """
        val = value.strip()
        if not re.match(r"^[a-zA-Z]+://", val):
            val = "http://" + val
        
        parsed = urlparse(val)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        
        # If the path is exactly '/' and there is no query/fragment, strip it for a cleaner base URL.
        # This keeps 'http://example.com/' and 'http://example.com' identical.
        if path == "/" and not parsed.query and not parsed.fragment:
            path = ""
            
        from urllib.parse import urlunparse
        return urlunparse((scheme, netloc, path, parsed.params, parsed.query, parsed.fragment))

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

