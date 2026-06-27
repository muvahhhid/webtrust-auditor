from webtrust_auditor.website_scanner import (
    contains_version_number,
    normalize_headers,
    normalize_url,
)


def test_normalize_url_adds_https_when_scheme_is_missing():
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_url_keeps_existing_https_scheme():
    assert normalize_url("https://example.com") == "https://example.com"


def test_normalize_headers_converts_names_to_lowercase():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
    }

    normalized = normalize_headers(headers)

    assert "content-security-policy" in normalized
    assert "x-frame-options" in normalized


def test_contains_version_number_detects_software_version():
    assert contains_version_number("Apache/2.4.49") is True
    assert contains_version_number("PHP/8.3.4") is True


def test_contains_version_number_ignores_name_without_version():
    assert contains_version_number("cloudflare") is False
    assert contains_version_number("nginx") is False