import dns.resolver
import dns.exception


def scan_email_domain(domain: str, dkim_selector: str | None = None) -> dict:
    """
    Performs passive email/domain security checks.

    This scanner only reads public DNS records.
    It does not send emails, spoof emails or attack any system.
    """
    clean_domain = normalize_domain(domain)

    result = {
        "domain": clean_domain,
        "mx_records": [],
        "spf_records": [],
        "dmarc_record": None,
        "dmarc_policy": None,
        "dkim_selector": dkim_selector,
        "dkim_record": None,
        "findings": [],
        "error": None
    }

    try:
        result["mx_records"] = get_mx_records(clean_domain)
        result["spf_records"] = get_spf_records(clean_domain)

        dmarc_record = get_dmarc_record(clean_domain)
        result["dmarc_record"] = dmarc_record
        result["dmarc_policy"] = extract_dmarc_policy(dmarc_record)

        if dkim_selector:
            result["dkim_record"] = get_dkim_record(clean_domain, dkim_selector)
        else:
            result["findings"].append({
                "title": "DKIM check skipped",
                "severity": "Info",
                "evidence": "No DKIM selector was provided.",
                "why": "DKIM records require a selector, for example google._domainkey.example.com.",
                "recommendation": "Run the scan again with --dkim-selector if you know the selector."
            })

        analyze_email_findings(result)

    except dns.exception.DNSException as error:
        result["error"] = str(error)

    return result


def normalize_domain(domain: str) -> str:
    """
    Removes protocol and path if the user accidentally enters a full URL.
    """
    cleaned = domain.strip()

    cleaned = cleaned.replace("https://", "")
    cleaned = cleaned.replace("http://", "")
    cleaned = cleaned.split("/")[0]

    return cleaned.lower()


def get_mx_records(domain: str) -> list:
    """
    Gets MX records for the domain.
    MX records define which mail servers receive email for the domain.
    """
    try:
        answers = dns.resolver.resolve(domain, "MX")
        records = []

        for record in answers:
            records.append(f"{record.preference} {str(record.exchange).rstrip('.')}")

        return records

    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []


def get_txt_records(name: str) -> list:
    """
    Gets TXT records and converts them into normal strings.
    """
    try:
        answers = dns.resolver.resolve(name, "TXT")
        records = []

        for record in answers:
            text = b"".join(record.strings).decode("utf-8", errors="ignore")
            records.append(text)

        return records

    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []


def get_spf_records(domain: str) -> list:
    """
    SPF records are TXT records that start with v=spf1.
    """
    txt_records = get_txt_records(domain)

    return [
        record for record in txt_records
        if record.lower().startswith("v=spf1")
    ]


def get_dmarc_record(domain: str) -> str | None:
    """
    DMARC is stored as a TXT record under _dmarc.domain.
    Example: _dmarc.example.com
    """
    dmarc_name = f"_dmarc.{domain}"
    txt_records = get_txt_records(dmarc_name)

    for record in txt_records:
        if record.lower().startswith("v=dmarc1"):
            return record

    return None


def extract_dmarc_policy(dmarc_record: str | None) -> str | None:
    """
    Extracts the p= policy from a DMARC record.
    Possible values: none, quarantine, reject.
    """
    if not dmarc_record:
        return None

    parts = dmarc_record.split(";")

    for part in parts:
        cleaned_part = part.strip().lower()

        if cleaned_part.startswith("p="):
            return cleaned_part.replace("p=", "").strip()

    return None


def get_dkim_record(domain: str, selector: str) -> str | None:
    """
    DKIM records require a selector.
    Example: google._domainkey.example.com
    """
    dkim_name = f"{selector}._domainkey.{domain}"
    txt_records = get_txt_records(dkim_name)

    for record in txt_records:
        if record.lower().startswith("v=dkim1"):
            return record

    return None


def analyze_email_findings(result: dict) -> None:
    """
    Converts DNS results into security findings.
    """
    has_mx = len(result["mx_records"]) > 0
    spf_count = len(result["spf_records"])

    if not has_mx:
        result["findings"].append({
            "title": "No MX records found",
            "severity": "Info",
            "evidence": "The domain does not have MX records.",
            "why": "MX records are required if the domain is expected to receive email.",
            "recommendation": "If the domain should receive email, configure MX records."
        })

    if spf_count == 0:
        severity = "Medium" if has_mx else "Info"

        result["findings"].append({
            "title": "SPF record is missing",
            "severity": severity,
            "evidence": "No TXT record starting with v=spf1 was found.",
            "why": "SPF helps define which servers are allowed to send email for the domain.",
            "recommendation": "Add an SPF record that includes only authorized mail senders."
        })

    if spf_count > 1:
        result["findings"].append({
            "title": "Multiple SPF records found",
            "severity": "Low",
            "evidence": f"{spf_count} SPF records were found.",
            "why": "Multiple SPF records can cause SPF validation failures.",
            "recommendation": "Merge SPF mechanisms into a single SPF record."
        })

    if result["dmarc_record"] is None:
        severity = "Medium" if has_mx else "Info"

        result["findings"].append({
            "title": "DMARC record is missing",
            "severity": severity,
            "evidence": f"No DMARC record was found at _dmarc.{result['domain']}.",
            "why": "DMARC helps protect domains from email spoofing and phishing abuse.",
            "recommendation": "Add a DMARC record and start with monitoring before moving to enforcement."
        })
    else:
        policy = result["dmarc_policy"]

        if policy is None:
            result["findings"].append({
                "title": "DMARC policy is missing",
                "severity": "Low",
                "evidence": "DMARC record exists, but no p= policy was found.",
                "why": "The p= value tells receivers what to do with suspicious emails.",
                "recommendation": "Add a DMARC policy such as p=none, p=quarantine or p=reject."
            })

        if policy == "none":
            result["findings"].append({
                "title": "DMARC policy is set to p=none",
                "severity": "Low",
                "evidence": "DMARC record uses p=none.",
                "why": "p=none is useful for monitoring, but it does not block suspicious emails.",
                "recommendation": "After monitoring, gradually move to p=quarantine and later p=reject."
            })

    if result["dkim_selector"] and result["dkim_record"] is None:
        result["findings"].append({
            "title": "DKIM record not found for selector",
            "severity": "Low",
            "evidence": f"No DKIM record was found for selector {result['dkim_selector']}.",
            "why": "DKIM helps prove that emails were authorized by the domain owner.",
            "recommendation": "Verify the DKIM selector or configure DKIM signing for the domain."
        })