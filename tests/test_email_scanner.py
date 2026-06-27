from webtrust_auditor.email_scanner import (
    extract_dmarc_policy,
    is_valid_domain_name,
    normalize_domain_input,
)


def test_normalize_domain_input_extracts_domain_from_email():
    domain, input_type = normalize_domain_input("22010903152@subu.edu.tr")

    assert domain == "subu.edu.tr"
    assert input_type == "email"


def test_normalize_domain_input_extracts_domain_from_url():
    domain, input_type = normalize_domain_input("https://www.example.com/path")

    assert domain == "www.example.com"
    assert input_type == "url"


def test_normalize_domain_input_keeps_domain_input():
    domain, input_type = normalize_domain_input("GitHub.COM")

    assert domain == "github.com"
    assert input_type == "domain"


def test_is_valid_domain_name_accepts_valid_domain():
    assert is_valid_domain_name("github.com") is True
    assert is_valid_domain_name("subu.edu.tr") is True


def test_is_valid_domain_name_rejects_invalid_domain():
    assert is_valid_domain_name("22010903152@subu.edu.tr") is False
    assert is_valid_domain_name("not-a-domain") is False
    assert is_valid_domain_name("example..com") is False


def test_extract_dmarc_policy_finds_none_policy():
    policy = extract_dmarc_policy("v=DMARC1; p=none; rua=mailto:dmarc@example.com")

    assert policy == "none"


def test_extract_dmarc_policy_finds_reject_policy():
    policy = extract_dmarc_policy("v=DMARC1; p=reject; adkim=s; aspf=s")

    assert policy == "reject"


def test_extract_dmarc_policy_returns_none_when_policy_missing():
    policy = extract_dmarc_policy("v=DMARC1; rua=mailto:dmarc@example.com")

    assert policy is None