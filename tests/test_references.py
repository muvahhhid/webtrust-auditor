from webtrust_auditor.references import enrich_finding_references


def test_enrich_references_maps_missing_csp():
    finding = {
        "title": "Missing Content-Security-Policy",
        "severity": "Medium",
    }

    enrich_finding_references(finding)

    assert finding["category"] == "Browser Security Hardening"
    assert "OWASP Top 10" in finding["owasp"]
    assert "CWE-693" in finding["cwe"]
    assert finding["references"]


def test_enrich_references_maps_exposed_env_file():
    finding = {
        "title": "Exposed environment file: /.env",
        "severity": "High",
    }

    enrich_finding_references(finding)

    assert finding["category"] == "Exposed Sensitive Configuration"
    assert "CWE-538" in finding["cwe"]
    assert finding["references"]


def test_enrich_references_maps_hardcoded_secret():
    finding = {
        "title": "Possible GitHub token found",
        "severity": "High",
    }

    enrich_finding_references(finding)

    assert finding["category"] == "Exposed Secret"
    assert "CWE-798" in finding["cwe"]
    assert finding["references"]