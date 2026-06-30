import re
from urllib.parse import urlparse

import dns.exception
import dns.resolver


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)


def scan_email_domain(domain: str, dkim_selector: str | None = None) -> dict:
    """
    Scans email/domain DNS security configuration.

    This function performs passive DNS lookups only.
    It does not send emails, authenticate, brute-force or modify anything.
    """
    normalized_domain, input_type = normalize_domain_input(domain)

    result = {
        "raw_input": domain,
        "input_type": input_type,
        "domain": normalized_domain,
        "domain_exists": False,
        "mx_records": [],
        "spf_records": [],
        "dmarc_record": None,
        "dmarc_policy": None,
        "dkim_selector": dkim_selector,
        "dkim_record": None,
        "observations": [],
        "findings": [],
        "error": None,
    }

    if not is_valid_domain_name(normalized_domain):
        result["error"] = (
            "Invalid domain input. Provide a domain such as example.com "
            "or an email address such as user@example.com."
        )
        result["findings"].append(
            {
                "title": "Invalid domain input",
                "severity": "High",
                "evidence": f"Input was normalized to: {normalized_domain}",
                "why": "Invalid domain input prevents reliable DNS and email security checks.",
                "recommendation": "Provide a valid domain such as example.com or an email address such as user@example.com.",
            }
        )
        return result

    result["domain_exists"] = domain_has_public_dns_records(normalized_domain)

    if not result["domain_exists"]:
        result["findings"].append(
            {
                "title": "Domain does not appear to exist",
                "severity": "High",
                "evidence": (
                    f"No public SOA, NS, A, AAAA, MX or TXT records were found for "
                    f"{normalized_domain}."
                ),
                "why": (
                    "If a domain has no public DNS records, email security checks cannot "
                    "be trusted and the domain may be invalid or misconfigured."
                ),
                "recommendation": (
                    "Verify that the domain is typed correctly and that it has public DNS records."
                ),
            }
        )

    check_mx_records(result)
    check_spf_records(result)
    check_dmarc_record(result)
    check_dkim_record(result, dkim_selector)

    return result


def normalize_domain_input(value: str) -> tuple[str, str]:
    """
    Normalizes user input into a domain name.

    Supported inputs:
    - example.com
    - user@example.com
    - https://example.com/path
    """
    cleaned_value = value.strip().lower()

    if "://" in cleaned_value:
        parsed_url = urlparse(cleaned_value)
        hostname = parsed_url.hostname or cleaned_value
        return hostname.rstrip("."), "url"

    if "@" in cleaned_value:
        email_domain = cleaned_value.rsplit("@", 1)[1]
        email_domain = email_domain.split("/", 1)[0]
        email_domain = email_domain.split(":", 1)[0]
        return email_domain.rstrip("."), "email"

    cleaned_value = cleaned_value.split("/", 1)[0]
    cleaned_value = cleaned_value.split(":", 1)[0]

    return cleaned_value.rstrip("."), "domain"


def is_valid_domain_name(domain: str) -> bool:
    """
    Validates a normal public domain name.
    """
    if not domain:
        return False

    if "@" in domain:
        return False

    if ".." in domain:
        return False

    return DOMAIN_PATTERN.match(domain) is not None


def domain_has_public_dns_records(domain: str) -> bool:
    """
    Checks whether the domain appears to exist in public DNS.
    """
    record_types = ["SOA", "NS", "A", "AAAA", "MX", "TXT"]

    for record_type in record_types:
        records = resolve_records(domain, record_type)

        if records:
            return True

    return False


def check_mx_records(result: dict) -> None:
    domain = result["domain"]
    mx_records = resolve_records(domain, "MX")

    result["mx_records"] = [
        str(record.exchange).rstrip(".") for record in mx_records
    ]

    if not result["mx_records"]:
        result["findings"].append(
            {
                "title": "No MX records found",
                "severity": "Medium",
                "evidence": f"No MX records were found for {domain}.",
                "why": (
                    "MX records define which mail servers receive email for the domain. "
                    "Without MX records, email delivery may not work as expected."
                ),
                "recommendation": (
                    "If the domain should receive email, configure valid MX records."
                ),
            }
        )


def check_spf_records(result: dict) -> None:
    domain = result["domain"]
    txt_records = resolve_txt_records(domain)

    spf_records = [
        record for record in txt_records
        if record.lower().startswith("v=spf1")
    ]

    result["spf_records"] = spf_records

    if not spf_records:
        result["findings"].append(
            {
                "title": "SPF record is missing",
                "severity": "Medium",
                "evidence": f"No SPF TXT record was found for {domain}.",
                "why": (
                    "SPF defines which mail servers are allowed to send email for the domain. "
                    "Without SPF, email spoofing is easier."
                ),
                "recommendation": (
                    "Add an SPF record that includes only authorized mail senders."
                ),
            }
        )
        return

    if len(spf_records) > 1:
        result["findings"].append(
            {
                "title": "Multiple SPF records found",
                "severity": "High",
                "evidence": f"{len(spf_records)} SPF records were found for {domain}.",
                "why": (
                    "A domain should have only one SPF record. Multiple SPF records can "
                    "cause SPF validation failures."
                ),
                "recommendation": (
                    "Merge all SPF mechanisms into a single SPF TXT record."
                ),
            }
        )
        return

    spf_record = spf_records[0].lower()

    if "+all" in spf_record:
        result["findings"].append(
            {
                "title": "SPF record allows all senders",
                "severity": "High",
                "evidence": spf_records[0],
                "why": (
                    "The +all mechanism allows any server to send email for the domain, "
                    "which makes spoofing much easier."
                ),
                "recommendation": (
                    "Replace +all with a restrictive mechanism such as -all or ~all."
                ),
            }
        )
        return

    if "?all" in spf_record:
        result["findings"].append(
            {
                "title": "SPF record uses neutral all mechanism",
                "severity": "Low",
                "evidence": spf_records[0],
                "why": (
                    "The ?all mechanism does not clearly reject unauthorized senders."
                ),
                "recommendation": (
                    "Use a stricter SPF ending such as -all or ~all when appropriate."
                ),
            }
        )
        return

    if "-all" not in spf_record and "~all" not in spf_record:
        result["findings"].append(
            {
                "title": "SPF record has no clear all mechanism",
                "severity": "Low",
                "evidence": spf_records[0],
                "why": (
                    "SPF records should normally end with an all mechanism to define how "
                    "unauthorized senders should be handled."
                ),
                "recommendation": (
                    "Review the SPF record and consider ending it with -all or ~all."
                ),
            }
        )


def check_dmarc_record(result: dict) -> None:
    domain = result["domain"]
    dmarc_domain = f"_dmarc.{domain}"
    txt_records = resolve_txt_records(dmarc_domain)

    dmarc_records = [
        record for record in txt_records
        if record.lower().startswith("v=dmarc1")
    ]

    if not dmarc_records:
        result["findings"].append(
            {
                "title": "DMARC record is missing",
                "severity": "Medium",
                "evidence": f"No DMARC TXT record was found at {dmarc_domain}.",
                "why": (
                    "DMARC helps domain owners protect against email spoofing and phishing "
                    "by defining how receivers should handle failed authentication."
                ),
                "recommendation": (
                    "Add a DMARC record and start with monitoring before moving to enforcement."
                ),
            }
        )
        return

    result["dmarc_record"] = dmarc_records[0]
    result["dmarc_policy"] = extract_dmarc_policy(dmarc_records[0])

    if not result["dmarc_policy"]:
        result["findings"].append(
            {
                "title": "DMARC policy is missing",
                "severity": "Medium",
                "evidence": dmarc_records[0],
                "why": (
                    "A DMARC record without a policy does not clearly define how failed "
                    "emails should be handled."
                ),
                "recommendation": (
                    "Add a DMARC policy such as p=none, p=quarantine or p=reject."
                ),
            }
        )
        return

    if result["dmarc_policy"] == "none":
        result["findings"].append(
            {
                "title": "DMARC policy is monitoring only",
                "severity": "Low",
                "evidence": dmarc_records[0],
                "why": (
                    "p=none is useful for monitoring, but it does not instruct receivers "
                    "to quarantine or reject suspicious emails."
                ),
                "recommendation": (
                    "After monitoring, consider moving to p=quarantine or p=reject."
                ),
            }
        )


def check_dkim_record(result: dict, dkim_selector: str | None) -> None:
    domain = result["domain"]

    if not dkim_selector:
        result["observations"].append(
            {
                "title": "DKIM check skipped",
                "details": (
                    "No DKIM selector was provided. Run the scan again with --dkim-selector "
                    "if you know the selector."
                ),
            }
        )
        return

    dkim_domain = f"{dkim_selector}._domainkey.{domain}"
    txt_records = resolve_txt_records(dkim_domain)

    dkim_records = [
        record for record in txt_records
        if "v=dkim1" in record.lower()
    ]

    if not dkim_records:
        result["findings"].append(
            {
                "title": "DKIM record was not found",
                "severity": "Medium",
                "evidence": f"No DKIM TXT record was found at {dkim_domain}.",
                "why": (
                    "DKIM helps prove that an email was authorized by the domain owner "
                    "and was not modified in transit."
                ),
                "recommendation": (
                    "Verify the DKIM selector and configure a DKIM record if the domain sends email."
                ),
            }
        )
        return

    result["dkim_record"] = dkim_records[0]


def resolve_records(domain: str, record_type: str) -> list:
    """
    Resolves DNS records safely and returns an empty list on common DNS failures.
    """
    try:
        return list(dns.resolver.resolve(domain, record_type))
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.resolver.LifetimeTimeout,
        dns.exception.Timeout,
    ):
        return []


def resolve_txt_records(domain: str) -> list[str]:
    """
    Resolves TXT records and joins split TXT chunks.
    """
    records = resolve_records(domain, "TXT")
    txt_values = []

    for record in records:
        if hasattr(record, "strings"):
            value = b"".join(record.strings).decode("utf-8", errors="ignore")
        else:
            value = record.to_text().strip('"')

        txt_values.append(value)

    return txt_values


def extract_dmarc_policy(dmarc_record: str) -> str | None:
    """
    Extracts the DMARC p= policy value.
    """
    parts = [part.strip().lower() for part in dmarc_record.split(";")]

    for part in parts:
        if part.startswith("p="):
            return part.split("=", 1)[1]

    return None