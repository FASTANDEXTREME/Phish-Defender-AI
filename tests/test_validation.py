import pytest
from app import _validate_domain

def test_validate_domain_valid():
    assert _validate_domain("example.com") == "example.com"
    assert _validate_domain("sub.example.co.uk") == "sub.example.co.uk"
    assert _validate_domain("https://example.com/some/path") == "https://example.com/some/path"

def test_validate_domain_empty():
    with pytest.raises(ValueError, match="Missing domain parameter"):
        _validate_domain("")
    with pytest.raises(ValueError, match="Missing domain parameter"):
        _validate_domain("   ")

def test_validate_domain_local_and_private_ips():
    blocked_inputs = [
        "localhost",
        "127.0.0.1",
        "https://127.0.0.1/admin",
        "http://10.0.0.5/internal",
        "192.168.1.1",
        "http://192.168.0.100:8080",
        "172.16.5.5",
        "172.31.255.255",
        "169.254.169.254",
        "http://169.254.169.254/latest/meta-data/",
        "0.0.0.0",
        "[::1]",
        "http://[::1]/",
        "http://[fc00::1]/",
    ]

    for input_domain in blocked_inputs:
        with pytest.raises(ValueError, match="Local/private domains are not allowed"):
            _validate_domain(input_domain)

def test_validate_domain_oversized():
    huge_domain = "a" * 260 + ".com"
    with pytest.raises(ValueError, match="Domain exceeds maximum length"):
        _validate_domain(huge_domain)
