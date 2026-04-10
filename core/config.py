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
    "societe generale": "societegenerale.com",
    "bnp paribas": "mabanque.bnpparibas",
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
    # AI / Cloud
    "openai": "openai.com",
    "chatgpt": "openai.com",
    "claude": "anthropic.com",
    "gemini": "gemini.google.com",
    # Telecom / ISP
    "att": "att.com",
    "xfinity": "xfinity.com",
    "comcast": "xfinity.com",
    "verizon": "verizon.com",
    "tmobile": "t-mobile.com",
    "t-mobile": "t-mobile.com",
    "talktalk": "talktalk.co.uk",
    "bellsouth": "att.com",
    "vodafone": "vodafone.com",
    "spectrum": "spectrum.net",
    "centurylink": "centurylink.com",
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
    "mtb": "mtb.com",
    "regions": "regions.com",
    "capitalone": "capitalone.com",
    "usbank": "usbank.com",
    "schwab": "schwab.com",
    "pnc": "pnc.com",
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
    "americanas": "americanas.com.br",
    "mercadolibre": "mercadolibre.com",
    # Hosting / Cloud services (for content impersonation detection)
    "dreamhost": "dreamhost.com",
    "godaddy": "godaddy.com",
    "bluehost": "bluehost.com",
    "hostgator": "hostgator.com",
    "wetransfer": "wetransfer.com",
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
# Brands frequently mentioned in footers or used for SSO (Social/Auth)
# These require stricter placement context to trigger brand impersonation.
# ---------------------------------------------------------------------------
SOCIAL_OR_SSO_BRANDS: List[str] = [
    "facebook", "linkedin", "instagram", "twitter", "x", "github", 
    "discord", "google", "apple", "microsoft"
]

# ---------------------------------------------------------------------------
# Ambiguous Brand Names — brands that are also common English words.
# These MUST appear in high-signal locations (title, h1/h2) to trigger brand
# impersonation. Body-text-only matches are ignored to prevent false positives
# on news sites, marketing pages, and general-purpose websites.
# ---------------------------------------------------------------------------
AMBIGUOUS_BRAND_NAMES: List[str] = [
    "chase", "regions", "meta", "wise", "ups", "spectrum",
    "outlook", "steam", "stripe", "slack", "discord", "spark",
    "signal", "tide", "heb", "allegro", "phantom", "ledger",
    "kraken", "coinbase", "opera", "vivaldi", "gemini",
]

# ---------------------------------------------------------------------------
# Brand Domain Aliases — maps sub-brands, alternate TLDs, and related domains
# to their parent organization's canonical domain. Used to prevent false
# positives when a parent site mentions its own sub-brand (e.g. bing.com
# mentioning "microsoft" is legitimate, not impersonation).
# ---------------------------------------------------------------------------
BRAND_DOMAIN_ALIASES: Dict[str, List[str]] = {
    "google.com": [
        "youtube.com", "googleapis.com", "googlesyndication.com",
        "google-analytics.com", "googledomains.com", "gstatic.com",
        "doubleclick.net", "googletagmanager.com", "googlevideo.com",
        "adtrafficquality.google", "pki.goog", "googleusercontent.com",
        "googleadservices.com", "goo.gl", "withgoogle.com",
        "blog.google", "domains.google", "about.google",
        "marketingplatform.google.com",
    ],
    "microsoft.com": [
        "outlook.com", "live.com", "office.com", "office365.com",
        "bing.com", "skype.com", "azure.com", "msn.com",
        "windowsupdate.com", "cloud.microsoft", "microsoftonline.com",
        "sharepoint.com", "windows.net", "windows.com",
        "teams.live.com", "m365.cloud.microsoft",
    ],
    "apple.com": [
        "icloud.com", "apple-dns.net", "cdn-apple.com", "itunes.com",
        "appstore.com",
    ],
    "meta.com": [
        "facebook.com", "instagram.com", "whatsapp.com", "fbcdn.net",
        "fb.com", "threads.net", "whatsapp.net",
    ],
    "amazon.com": [
        "amazonaws.com", "amazonvideo.com", "amazon-adsystem.com",
        "a2z.com", "primevideo.com", "aws.dev", "aws.amazon.com",
        "amazon.dev",
    ],
    "discord.com": ["discord.gg", "discordapp.com"],
    "github.com": ["github.io", "githubusercontent.com"],
    "twitter.com": ["x.com", "t.co"],
    "telegram.org": ["t.me", "telegram.me"],
    "cloudflare.com": [
        "cloudflare-dns.com", "cloudflare.net", "workers.dev",
        "pages.dev", "one.one.one.one",
    ],
    "adobe.com": ["adobe.io", "macromedia.com"],
    "automattic.com": ["wordpress.com", "wordpress.org", "gravatar.com"],
    "yahoo.com": ["flickr.com", "tumblr.com"],
    "spotify.com": ["spotifycdn.com"],
    "tiktok.com": ["tiktokcdn.com", "tiktokv.com", "tiktokcdn-us.com"],
    "netflix.com": ["nflxso.net", "nflxext.com", "nflxvideo.net"],
    "shopify.com": ["myshopify.com", "shopifycloud.com"],
    "vk.com": ["vkuserphoto.ru", "userapi.com"],
    "yandex.ru": ["yandex.net", "yandex.com"],
    "samsung.com": ["samsungcloud.com"],
    "xiaomi.com": ["mi.com", "miui.com"],
    "zoom.us": ["zoom.com"],
    "paypal.com": ["paypalobjects.com"],
    "ebay.com": ["ebayimg.com", "ebaystatic.com"],
    "linkedin.com": ["licdn.com"],
    "pinterest.com": ["pinimg.com"],
    "snapchat.com": ["snap.com", "snapkit.com"],
    "twitch.tv": ["twitchcdn.net", "jtvnw.net"],
    "reddit.com": ["redd.it", "redditstatic.com"],
    "dropbox.com": ["dropboxapi.com", "dropboxstatic.com"],
    "intuit.com": ["turbotax.com", "quickbooks.com", "mint.com"],
    "att.com": ["bellsouth.net"],
}

# ---------------------------------------------------------------------------
# Granular Brand Intelligence Tiers (Brand Tier Mapping)
# ---------------------------------------------------------------------------
BRAND_TIERS: Dict[str, str] = {
    "paypal": "finance_global",
    "stripe": "finance_global",
    "chase": "finance_global",
    "wellsfargo": "finance_global",
    "bankofamerica": "finance_global",
    "citibank": "finance_global",
    "societe generale": "finance_eu",
    "bnp paribas": "finance_eu",
    "barclays": "finance_eu",
    "hsbc": "finance_global",
    "facebook": "tech_social",
    "instagram": "tech_social",
    "apple": "tech_social",
    "microsoft": "tech_social",
    "google": "tech_social",
}

# ---------------------------------------------------------------------------
# Free Hosting Platforms (commonly abused for throwaway subdomains)
# ---------------------------------------------------------------------------
KNOWN_HOSTING_PLATFORMS: List[str] = [
    # Website builders
    "vercel.app", "webflow.io", "wixstudio.com", "wix.com",
    "weebly.com", "weeblysite.com",  # Both Weebly domains
    "squarespace.com", "godaddysites.com", "site123.me",
    "wordpress.com", "blogspot.com",
    # Developer / PaaS platforms
    "github.io", "pages.dev", "netlify.app", "herokuapp.com",
    "firebaseapp.com", "web.app", "replit.dev", "glitch.me",
    "onrender.com", "railway.app", "fly.dev", "surge.sh",
    "pythonanywhere.com", "ondigitalocean.app",
    # Cloud storage / CDN (commonly abused for static phishing pages)
    "amazonaws.com", "cloudflare.net", "r2.dev",
    "core.windows.net", "blob.core.windows.net", "web.core.windows.net",
    "azurewebsites.net", "azurestaticapps.net",
    # Automation / low-code
    "zapier.app", "lovable.app", "edgeone.app", "appwrite.network",
    # Dynamic DNS (throwaway subdomains)
    "duckdns.org", "ddns.net", "no-ip.com", "freedns.afraid.org",
    # Other free hosting
    "mystagingwebsite.com", "kesug.com", "pantheonsite.io",
    "tiiny.site", "000webhostapp.com", "infinityfreeapp.com",
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
# Suspicious path patterns (I4)
# ---------------------------------------------------------------------------
SUSPICIOUS_PATHS: List[str] = [
    r"/checkpoint", r"/verify", r"/wp-forms", r"/auth", r"/secure",
    r"/login", r"/signin", r"/account", r"/update", r"/billing", r"/payment"
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
# Payment / Credit card keywords (C6: sensitive field detection)
# ---------------------------------------------------------------------------
PAYMENT_KEYWORDS: List[str] = [
    "card number", "card info", "card information", "credit card", "debit card",
    "cvv", "cvc", "security code", "expiry", "exp date", "expiration date",
    "mm/yy", "mm / yy", "mm/yyyy", "cardholder", "card holder",
    "billing address", "payment method", "pay now", "checkout",
    "subscribe with obligation", "add payment", "enter card",
]

# ---------------------------------------------------------------------------
# Tech support scam indicators (C6)
# ---------------------------------------------------------------------------
SCAM_KEYWORDS: List[str] = [
    "call support", "tech help", "tech support", "system warning",
    "virus detected", "virus found", "computer locked", "computer infected",
    "call microsoft", "call apple", "call windows",
    "toll free", "toll-free",
    "your computer has been", "windows alert", "windows defender",
    "system alert", "security alert",
    "malware detected", "malware found",
    "system operation suspended", "activate your license",
    "manual scan is required",
]

# ---------------------------------------------------------------------------
# OTP / Verification code keywords (C6) - Multilingual
# ---------------------------------------------------------------------------
INTENT_OTP: Dict[str, List[str]] = {
    "en": [
        "verification code", "one-time password", "one-time code",
        "otp", "6-digit code", "4-digit code", "authentication code",
        "security code", "enter the code", "enter code",
        "code sent to", "we sent a code"
    ],
    "de": ["anmeld", "code", "bestätigung", "kennwort", "sicherheitscode", "anmeldecode"],
    "fr": ["code de vérification", "mot de passe", "code client"],
    "es": ["código", "contraseña", "verificación"]
}

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
    "similarity": 0.30,       # I2: Was 0.15 — brand detection needs higher weight
    "intelligence": 0.30,     # I2: Was 0.45 — useless for hosted platform subdomains
    "content": 0.40,          # Unchanged — content analysis remains primary signal
}

# ---------------------------------------------------------------------------
# Cross-Reference Engine (CRE) scoring parameters
# ---------------------------------------------------------------------------
CRE_BRAND_CONTENT_MISMATCH_RISK: float = 0.35   # Brand in body text only — reduced from 0.75
CRE_BRAND_STRONG_MISMATCH_RISK: float = 0.65    # Brand in title/heading — strong impersonation signal
CRE_BRAND_DOMAIN_MISMATCH_RISK: float = 0.55    # Brand in subdomain on hosted platform
CRE_HOSTED_BRAND_IMPERSONATION_RISK: float = 0.90  # All 3 signals = near certain phishing
CRE_BRAND_PLUS_CREDENTIAL_RISK: float = 0.80    # Brand impersonation + credential collection
CRE_PAYMENT_ON_DISPOSABLE_RISK: float = 0.70    # Payment form on new/hosted domain
CRE_SCAM_ON_DISPOSABLE_RISK: float = 0.65       # Scam indicators on new/hosted domain

# When CRE has a nonzero signal, use these weights (4-way split)
SCORING_WEIGHTS_WITHOUT_SB_WITH_CRE = {
    "similarity": 0.20,
    "intelligence": 0.20,
    "content": 0.30,
    "cross_reference": 0.30,
}

# ---------------------------------------------------------------------------
# Classification thresholds
# Max possible score without SB is 1.0 now (with new sim scoring).
# Lowered from 0.7/0.4 so agents can trigger classification independently.
# ---------------------------------------------------------------------------
PHISHING_THRESHOLD: float = 0.55
SUSPICIOUS_THRESHOLD: float = 0.35

# ---------------------------------------------------------------------------
# Signal amplification: if N agents report high risk, boost the score
# ---------------------------------------------------------------------------
CORROBORATION_THRESHOLD: int = 2   # number of high-risk agents needed
CORROBORATION_BOOST: float = 1.25  # 25% boost for agreement (reduced from 1.50 to prevent score inflation)

__all__ = [
    "KNOWN_BRANDS",
    "KNOWN_HOSTING_PLATFORMS",
    "BRAND_TIERS",
    "UNICODE_HOMOGLYPHS",
    "HOMOGLYPH_TRANSLATE",
    "PHISHING_DOMAIN_KEYWORDS",
    "SUSPICIOUS_PATHS",
    "SUSPICIOUS_CONTENT_KEYWORDS",
    "PAYMENT_KEYWORDS",
    "SCAM_KEYWORDS",
    "INTENT_OTP",
    "SCORING_WEIGHTS_WITH_SB",
    "SCORING_WEIGHTS_WITHOUT_SB",
    "SCORING_WEIGHTS_WITHOUT_SB_WITH_CRE",
    "CRE_BRAND_CONTENT_MISMATCH_RISK",
    "CRE_BRAND_STRONG_MISMATCH_RISK",
    "CRE_BRAND_DOMAIN_MISMATCH_RISK",
    "CRE_HOSTED_BRAND_IMPERSONATION_RISK",
    "CRE_BRAND_PLUS_CREDENTIAL_RISK",
    "CRE_PAYMENT_ON_DISPOSABLE_RISK",
    "CRE_SCAM_ON_DISPOSABLE_RISK",
    "PHISHING_THRESHOLD",
    "SUSPICIOUS_THRESHOLD",
    "CORROBORATION_THRESHOLD",
    "CORROBORATION_BOOST",
    "SOCIAL_OR_SSO_BRANDS",
    "AMBIGUOUS_BRAND_NAMES",
    "BRAND_DOMAIN_ALIASES",
]

