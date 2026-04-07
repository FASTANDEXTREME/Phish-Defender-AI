import pytest
from agents.domain_similarity_agent import DomainSimilarityAgent
from agents.website_content_agent import WebsiteContentAgent
from bs4 import BeautifulSoup

def test_domain_similarity_exact_brand_wrong_tld():
    agent = DomainSimilarityAgent()
    # "paypal" is a known brand configured in config.py
    # Canonical is paypal.com. The .net version should be flagged as suspicious, NOT SAFE (0.0).
    result = agent.run("paypal.net")
    assert result.risk_score > 0.0
    assert result.similarity_score > 0.0
    brand_hit = (result.brand_name or result.closest_brand or "").lower()
    assert "paypal" in brand_hit

def test_domain_similarity_lookalike_brand():
    agent = DomainSimilarityAgent()
    result = agent.run("login-paypal-security.com")
    assert result.risk_score > 0.0
    assert "paypal" in result.brand_name.lower()

def test_website_content_brand_impersonation_bypass():
    agent = WebsiteContentAgent()
    # Mocking the HTML content with OpenAI keywords
    html = """
    <html>
        <title>OpenAI Support Login</title>
        <body>
            Welcome to ChatGPT support. Enter your password.
        </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    # If the domain is openai-support.com, previously it bypassed because 'openai' in 'openai-support.com'
    visible_text = soup.get_text()
    impersonated = agent._detect_brand_impersonation(soup, visible_text, "OpenAI Support Login", "openai-support.com")
    
    assert len(impersonated) > 0
    assert "openai" in impersonated
