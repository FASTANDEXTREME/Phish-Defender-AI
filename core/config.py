"""
Centralized configuration for the Phish-Defender AI system.

All tunable constants, brand lists, keyword lists, scoring weights, and
thresholds live here so agents stay lean and changes are made in one place.
"""

from __future__ import annotations
from typing import Dict, List

# ---------------------------------------------------------------------------
# Known brand targets (name → canonical domain)
# ---------------------------------------------------------------------------
KNOWN_BRANDS: Dict[str, str] = {
    # Big Tech
    "google": "google.com",
    "facebook": "facebook.com",
    "meta": "meta.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "linkedin": "linkedin.com",
    "instagram": "instagram.com",
    "twitter": "twitter.com",
    "x": "x.com",
    "whatsapp": "whatsapp.com",
    "telegram": "telegram.org",
    "zoom": "zoom.us",
    "dropbox": "dropbox.com",
    "slack": "slack.com",
    "github": "github.com",
    "gitlab": "gitlab.com",
    "spotify": "spotify.com",
    "tiktok": "tiktok.com",
    "snapchat": "snapchat.com",
    "pinterest": "pinterest.com",
    "reddit": "reddit.com",
    "discord": "discord.com",
    "yahoo": "yahoo.com",
    "outlook": "outlook.com",
    "icloud": "icloud.com",
    # Finance / Banking
    "paypal": "paypal.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "citibank": "citibank.com",
    "hsbc": "hsbc.com",
    "barclays": "barclays.co.uk",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
    "sbi": "onlinesbi.com",
    "axisbank": "axisbank.com",
    "kotak": "kotak.com",
    "stripe": "stripe.com",
    "wise": "wise.com",
    "venmo": "venmo.com",
    "cashapp": "cash.app",
    # Crypto
    "coinbase": "coinbase.com",
    "binance": "binance.com",
    "kraken": "kraken.com",
    "metamask": "metamask.io",
    "kucoin": "kucoin.com",
    "trezor": "trezor.io",
    "ledger": "ledger.com",
    "solflare": "solflare.com",
    "rabby": "rabby.io",
    "phantom": "phantom.app",
    # E-commerce
    "ebay": "ebay.com",
    "walmart": "walmart.com",
    "shopify": "shopify.com",
    "flipkart": "flipkart.com",
    "alibaba": "alibaba.com",
    "allegro": "allegro.pl",
    "heb": "heb.com",
    # Government / Services
    "irs": "irs.gov",
    "usps": "usps.com",
    "fedex": "fedex.com",
    "dhl": "dhl.com",
    "ups": "ups.com",
    "docomo": "docomo.ne.jp",
    "optus": "optus.com.au",
    "mondial": "mondialrelay.fr",
    "mondialrelay": "mondialrelay.fr",
    # Gaming
    "steam": "steampowered.com",
    "epicgames": "epicgames.com",
    "roblox": "roblox.com",
}

# ---------------------------------------------------------------------------
# Free Hosting Platforms (commonly abused for throwaway subdomains)
# ---------------------------------------------------------------------------
KNOWN_HOSTING_PLATFORMS: List[str] = [
    "vercel.app", "webflow.io", "wixstudio.com", "github.io", "pages.dev",
    "zapier.app", "lovable.app", "godaddysites.com", "web.app", "replit.dev",
    "edgeone.app", "weebly.com", "mystagingwebsite.com", "kesug.com",
    "amazonaws.com", "cloudflare.net", "herokuapp.com", "firebaseapp.com",
    "netlify.app", "glitch.me", "onrender.com", "site123.me", "pantheonsite.io"
]

# ---------------------------------------------------------------------------
# Unicode homoglyphs (Cyrillic / IPA → Latin equivalents)
# ---------------------------------------------------------------------------
UNICODE_HOMOGLYPHS: Dict[str, str] = {
    # Cyrillic confusables
    "\u0430": "a",  # а → a
    "\u0435": "e",  # е → e
    "\u043e": "o",  # о → o
    "\u0440": "p",  # р → p
    "\u0441": "c",  # с → c
    "\u0443": "y",  # у → y
    "\u0445": "x",  # х → x
    "\u043a": "k",  # к → k
    "\u043d": "h",  # н → h
    "\u0456": "i",  # і → i
    "\u0458": "j",  # ј → j
    # ASCII look-alikes
    "0": "o",
    "1": "l",
    "@": "a",
    "3": "e",
    "5": "s",
    "7": "t",
    "$": "s",
    "!": "i",
    # Latin look-alikes (IPA / extended)
    "\u0261": "g",  # ɡ → g
    "\u0131": "i",  # ı → i
    "\u0127": "h",  # ħ → h
}

HOMOGLYPH_TRANSLATE = str.maketrans(UNICODE_HOMOGLYPHS)

# ---------------------------------------------------------------------------
# Phishing keywords found in domain names (e.g. login-paypal-secure.com)
# ---------------------------------------------------------------------------
PHISHING_DOMAIN_KEYWORDS: List[str] = [
    "login", "signin", "sign-in", "secure", "verify", "update",
    "confirm", "account", "alert", "support", "service", "billing",
    "suspend", "restore", "unlock", "authentication", "validate",
    "recovery", "helpdesk", "security", "password",
]

# ---------------------------------------------------------------------------
# Suspicious keywords in page content
# ---------------------------------------------------------------------------
SUSPICIOUS_CONTENT_KEYWORDS: List[str] = [
    # Original set
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
    # Expanded set — urgency & social-engineering
    "your account has been",
    "click here to restore",
    "within 24 hours",
    "within 48 hours",
    "failure to comply",
    "unauthorized access",
    "limited time",
    "verify your information",
    "update your details",
    "confirm your identity",
    "reactivate your account",
    "your account will be",
    "sign in to continue",
    "enter your credentials",
    "billing information",
    "payment declined",
    "suspicious login",
    "reset your password",
    "we detected unusual",
    "action required",
]

# ---------------------------------------------------------------------------
# Scoring weights for the Decision Agent
# When Safe Browsing returns no threat (risk=0.0), its weight is dead weight
# that suppresses other agents. Use separate weight sets.
# ---------------------------------------------------------------------------
SCORING_WEIGHTS_WITH_SB = {
    "similarity": 0.25,
    "intelligence": 0.20,
    "content": 0.20,
    "safe_browsing": 0.35,
}
SCORING_WEIGHTS_WITHOUT_SB = {
    "similarity": 0.15,
    "intelligence": 0.45,
    "content": 0.40,
}

# ---------------------------------------------------------------------------
# Classification thresholds
# Max possible score without SB is 1.0 now (with new sim scoring).
# Lowered from 0.7/0.4 so agents can trigger classification independently.
# ---------------------------------------------------------------------------
PHISHING_THRESHOLD: float = 0.45
SUSPICIOUS_THRESHOLD: float = 0.30

# ---------------------------------------------------------------------------
# Signal amplification: if N agents report high risk, boost the score
# ---------------------------------------------------------------------------
CORROBORATION_THRESHOLD: int = 2   # number of high-risk agents needed
CORROBORATION_BOOST: float = 1.50  # 50% boost for agreement

__all__ = [
    "KNOWN_BRANDS",
    "KNOWN_HOSTING_PLATFORMS",
    "UNICODE_HOMOGLYPHS",
    "HOMOGLYPH_TRANSLATE",
    "PHISHING_DOMAIN_KEYWORDS",
    "SUSPICIOUS_CONTENT_KEYWORDS",
    "SCORING_WEIGHTS_WITH_SB",
    "SCORING_WEIGHTS_WITHOUT_SB",
    "PHISHING_THRESHOLD",
    "SUSPICIOUS_THRESHOLD",
    "CORROBORATION_THRESHOLD",
    "CORROBORATION_BOOST",
]
