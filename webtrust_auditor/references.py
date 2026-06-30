OWASP_REFERENCES = {
    "A02": "OWASP Top 10 A02:2021 - Cryptographic Failures",
    "A05": "OWASP Top 10 A05:2021 - Security Misconfiguration",
    "A06": "OWASP Top 10 A06:2021 - Vulnerable and Outdated Components",
    "A07": "OWASP Top 10 A07:2021 - Identification and Authentication Failures",
}

CWE_REFERENCES = {
    "CWE-200": "CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-295": "CWE-295 - Improper Certificate Validation",
    "CWE-319": "CWE-319 - Cleartext Transmission of Sensitive Information",
    "CWE-522": "CWE-522 - Insufficiently Protected Credentials",
    "CWE-530": "CWE-530 - Exposure of Backup File to an Unauthorized Control Sphere",
    "CWE-538": "CWE-538 - Insertion of Sensitive Information into Externally-Accessible File or Directory",
    "CWE-693": "CWE-693 - Protection Mechanism Failure",
    "CWE-798": "CWE-798 - Use of Hard-coded Credentials",
    "CWE-1021": "CWE-1021 - Improper Restriction of Rendered UI Layers or Frames",
}


REFERENCE_URLS = {
    "OWASP_A02": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "OWASP_A05": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "OWASP_A06": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    "OWASP_A07": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    "CWE_200": "https://cwe.mitre.org/data/definitions/200.html",
    "CWE_295": "https://cwe.mitre.org/data/definitions/295.html",
    "CWE_319": "https://cwe.mitre.org/data/definitions/319.html",
    "CWE_522": "https://cwe.mitre.org/data/definitions/522.html",
    "CWE_530": "https://cwe.mitre.org/data/definitions/530.html",
    "CWE_538": "https://cwe.mitre.org/data/definitions/538.html",
    "CWE_693": "https://cwe.mitre.org/data/definitions/693.html",
    "CWE_798": "https://cwe.mitre.org/data/definitions/798.html",
    "CWE_1021": "https://cwe.mitre.org/data/definitions/1021.html",
}


def enrich_result_references(result: dict | None) -> dict | None:
    """
    Adds professional security references to findings.

    Observations are intentionally not enriched because they are not security findings.
    """
    if not result:
        return result

    for finding in result.get("findings", []):
        enrich_finding_references(finding)

    return result


def enrich_finding_references(finding: dict) -> dict:
    """
    Adds category, OWASP, CWE and reference URLs based on the finding title.
    """
    title = finding.get("title", "").lower()
    category = finding.get("category")
    owasp = finding.get("owasp")
    cwe = finding.get("cwe")
    references = finding.get("references", [])

    if not category:
        category = "Security Finding"

    if "content-security-policy" in title or "permissions-policy" in title:
        category = "Browser Security Hardening"
        owasp = OWASP_REFERENCES["A05"]
        cwe = CWE_REFERENCES["CWE-693"]
        references = [REFERENCE_URLS["OWASP_A05"], REFERENCE_URLS["CWE_693"]]

    elif "strict-transport-security" in title or "hsts" in title:
        category = "Transport Security Misconfiguration"
        owasp = OWASP_REFERENCES["A02"]
        cwe = CWE_REFERENCES["CWE-319"]
        references = [REFERENCE_URLS["OWASP_A02"], REFERENCE_URLS["CWE_319"]]

    elif "x-frame-options" in title or "clickjacking" in title:
        category = "Clickjacking Protection"
        owasp = OWASP_REFERENCES["A05"]
        cwe = CWE_REFERENCES["CWE-1021"]
        references = [REFERENCE_URLS["OWASP_A05"], REFERENCE_URLS["CWE_1021"]]

    elif "x-content-type-options" in title or "referrer-policy" in title:
        category = "Browser Security Hardening"
        owasp = OWASP_REFERENCES["A05"]
        cwe = CWE_REFERENCES["CWE-693"]
        references = [REFERENCE_URLS["OWASP_A05"], REFERENCE_URLS["CWE_693"]]

    elif "https" in title or "ssl" in title or "certificate" in title:
        category = "Transport Security"
        owasp = OWASP_REFERENCES["A02"]
        cwe = CWE_REFERENCES["CWE-295"]
        references = [REFERENCE_URLS["OWASP_A02"], REFERENCE_URLS["CWE_295"]]

    elif "version disclosure" in title or "software version" in title:
        category = "Information Disclosure"
        owasp = OWASP_REFERENCES["A05"]
        cwe = CWE_REFERENCES["CWE-200"]
        references = [REFERENCE_URLS["OWASP_A05"], REFERENCE_URLS["CWE_200"]]

    elif "spf" in title or "dmarc" in title or "dkim" in title or "mx records" in title:
        category = "Email Authentication Misconfiguration"
        owasp = OWASP_REFERENCES["A05"]
        cwe = "Not directly mapped"
        references = [REFERENCE_URLS["OWASP_A05"]]

    elif "domain does not appear to exist" in title or "invalid domain" in title:
        category = "Domain Configuration Issue"
        owasp = OWASP_REFERENCES["A05"]
        cwe = "Not directly mapped"
        references = [REFERENCE_URLS["OWASP_A05"]]

    elif "github token" in title or "aws key" in title or "secret" in title or "private key" in title or "jwt" in title:
        category = "Exposed Secret"
        owasp = OWASP_REFERENCES["A07"]
        cwe = CWE_REFERENCES["CWE-798"]
        references = [REFERENCE_URLS["OWASP_A07"], REFERENCE_URLS["CWE_798"]]

    elif ".env" in title or "environment file" in title:
        category = "Exposed Sensitive Configuration"
        owasp = OWASP_REFERENCES["A05"]
        cwe = CWE_REFERENCES["CWE-538"]
        references = [REFERENCE_URLS["OWASP_A05"], REFERENCE_URLS["CWE_538"]]

    elif ".git" in title or "git repository" in title:
        category = "Source Code Exposure"
        owasp = OWASP_REFERENCES["A05"]
        cwe = CWE_REFERENCES["CWE-200"]
        references = [REFERENCE_URLS["OWASP_A05"], REFERENCE_URLS["CWE_200"]]

    elif "backup" in title or "database dump" in title or "sql dump" in title:
        category = "Exposed Backup or Database Dump"
        owasp = OWASP_REFERENCES["A05"]
        cwe = CWE_REFERENCES["CWE-530"]
        references = [REFERENCE_URLS["OWASP_A05"], REFERENCE_URLS["CWE_530"]]

    elif "phpinfo" in title or "debug" in title or "server-status" in title or "server-info" in title:
        category = "Information Disclosure"
        owasp = OWASP_REFERENCES["A05"]
        cwe = CWE_REFERENCES["CWE-200"]
        references = [REFERENCE_URLS["OWASP_A05"], REFERENCE_URLS["CWE_200"]]

    elif "source map" in title or "package file" in title or "dependency file" in title:
        category = "Information Disclosure"
        owasp = OWASP_REFERENCES["A05"]
        cwe = CWE_REFERENCES["CWE-200"]
        references = [REFERENCE_URLS["OWASP_A05"], REFERENCE_URLS["CWE_200"]]

    finding["category"] = category
    finding["owasp"] = owasp or "Not directly mapped"
    finding["cwe"] = cwe or "Not directly mapped"
    finding["references"] = references

    return finding