import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "Medium",
        "why": "Helps reduce the impact of Cross-Site Scripting attacks."
    },
    "Strict-Transport-Security": {
        "severity": "Medium",
        "why": "Forces browsers to use HTTPS for future requests."
    },
    "X-Frame-Options": {
        "severity": "Low",
        "why": "Helps protect against clickjacking attacks."
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "why": "Prevents browsers from MIME-sniffing responses."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "why": "Controls how much referrer information is sent to other sites."
    },
    "Permissions-Policy": {
        "severity": "Low",
        "why": "Limits browser features such as camera, microphone or geolocation."
    }
}


VERSION_DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator"
]


VERSION_PATTERN = re.compile(
    r"\b\d+(?:\.\d+){1,4}(?:[-_a-zA-Z0-9.]*)?\b"
)


def normalize_url(url: str) -> str:
    """
    Ensures the URL has http:// or https://.
    If the user writes example.com, it becomes https://example.com.
    """
    if not url.startswith(("http://", "https://")):
        return "https://" + url

    return url


def scan_website(url: str) -> dict:
    """
    Scans a website for basic security readiness checks.

    This function does not attack the website.
    It only sends a normal HTTP GET request and reads response headers.
    """
    normalized_url = normalize_url(url)

    result = {
        "target_url": normalized_url,
        "final_url": None,
        "status_code": None,
        "is_https": False,
        "headers": {},
        "headers_lower": {},
        "ssl_certificate": {
            "checked": False,
            "not_before": None,
            "not_after": None,
            "days_until_expiry": None,
            "issuer": None,
            "subject": None,
            "error": None
        },
        "findings": [],
        "error": None
    }

    try:
        response = requests.get(
            normalized_url,
            timeout=30,
            allow_redirects=True,
            headers={
                "User-Agent": "WebTrust-Auditor/1.2"
            }
        )

        result["final_url"] = response.url
        result["status_code"] = response.status_code
        result["headers"] = dict(response.headers)
        result["headers_lower"] = normalize_headers(response.headers)

        parsed_final_url = urlparse(response.url)
        result["is_https"] = parsed_final_url.scheme == "https"

        if not result["is_https"]:
            result["findings"].append({
                "title": "Website is not using HTTPS",
                "severity": "High",
                "evidence": f"Final URL uses scheme: {parsed_final_url.scheme}",
                "why": "Without HTTPS, data between the user and the website can be intercepted.",
                "recommendation": "Enable HTTPS and redirect all HTTP traffic to HTTPS."
            })

        check_security_headers(result)
        check_version_disclosure_headers(result)

        if result["is_https"]:
            check_ssl_certificate(result)

    except requests.exceptions.RequestException as error:
        result["error"] = str(error)

    return result


def normalize_headers(headers) -> dict:
    """
    Converts response headers to a lowercase dictionary.

    HTTP header names are case-insensitive.
    """
    return {
        str(header_name).lower(): header_value
        for header_name, header_value in headers.items()
    }


def check_security_headers(result: dict) -> None:
    """
    Checks whether important security headers exist.
    Header names are checked case-insensitively.
    """
    headers_lower = result.get("headers_lower", {})

    for header_name, header_info in SECURITY_HEADERS.items():
        if header_name.lower() not in headers_lower:
            result["findings"].append({
                "title": f"Missing {header_name}",
                "severity": header_info["severity"],
                "evidence": f"{header_name} header was not found.",
                "why": header_info["why"],
                "recommendation": f"Add the {header_name} header to improve browser-side security."
            })


def check_version_disclosure_headers(result: dict) -> None:
    """
    Checks whether response headers expose exact software versions.

    Example:
    Server: Apache/2.4.49
    X-Powered-By: PHP/8.3.4
    """
    headers_lower = result.get("headers_lower", {})

    for header_name in VERSION_DISCLOSURE_HEADERS:
        header_value = headers_lower.get(header_name.lower())

        if not header_value:
            continue

        if contains_version_number(header_value):
            result["findings"].append({
                "title": "Software version disclosure detected",
                "severity": "Low",
                "evidence": f"{header_name}: {header_value}",
                "why": (
                    "Exposing exact software versions can help attackers identify "
                    "known vulnerabilities for the detected technology."
                ),
                "recommendation": (
                    f"Avoid exposing exact version information in the {header_name} header "
                    "where possible. Review server/framework configuration."
                )
            })


def contains_version_number(value: str) -> bool:
    """
    Detects whether a header value appears to contain a software version number.
    """
    return VERSION_PATTERN.search(value) is not None


def check_ssl_certificate(result: dict) -> None:
    """
    Checks SSL certificate validity dates for the final HTTPS URL.
    """
    final_url = result.get("final_url")

    if not final_url:
        return

    parsed_url = urlparse(final_url)
    hostname = parsed_url.hostname
    port = parsed_url.port or 443

    if not hostname:
        return

    result["ssl_certificate"]["checked"] = True

    try:
        cert = get_ssl_certificate(hostname, port)
        not_before = parse_ssl_datetime(cert.get("notBefore"))
        not_after = parse_ssl_datetime(cert.get("notAfter"))

        result["ssl_certificate"]["not_before"] = format_datetime(not_before)
        result["ssl_certificate"]["not_after"] = format_datetime(not_after)
        result["ssl_certificate"]["days_until_expiry"] = calculate_days_until(not_after)
        result["ssl_certificate"]["issuer"] = extract_common_name(cert.get("issuer", ()))
        result["ssl_certificate"]["subject"] = extract_common_name(cert.get("subject", ()))

        add_ssl_findings(result)

    except (OSError, ssl.SSLError, ValueError) as error:
        result["ssl_certificate"]["error"] = str(error)
        result["findings"].append({
            "title": "SSL certificate check failed",
            "severity": "Info",
            "evidence": f"Could not inspect SSL certificate for {hostname}: {error}",
            "why": "The scanner could not read certificate metadata for this HTTPS endpoint.",
            "recommendation": "Verify the SSL certificate manually if certificate status is important."
        })


def get_ssl_certificate(hostname: str, port: int) -> dict:
    """
    Opens a normal TLS connection and reads the peer certificate.
    """
    context = ssl.create_default_context()

    with socket.create_connection((hostname, port), timeout=10) as tcp_socket:
        with context.wrap_socket(tcp_socket, server_hostname=hostname) as tls_socket:
            return tls_socket.getpeercert()


def parse_ssl_datetime(value: str | None) -> datetime:
    """
    Parses SSL certificate date format.
    Example: Jun 22 12:00:00 2026 GMT
    """
    if not value:
        raise ValueError("SSL certificate date is missing.")

    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )


def calculate_days_until(expiry_date: datetime) -> int:
    """
    Calculates how many days remain until SSL certificate expiry.
    """
    now = datetime.now(timezone.utc)
    return (expiry_date - now).days


def format_datetime(value: datetime | None) -> str | None:
    """
    Formats datetime for report and terminal output.
    """
    if not value:
        return None

    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def extract_common_name(name_tuple) -> str | None:
    """
    Extracts commonName from SSL subject or issuer tuple.
    """
    for group in name_tuple:
        for key, value in group:
            if key == "commonName":
                return value

    return None


def add_ssl_findings(result: dict) -> None:
    """
    Adds findings based on SSL certificate expiry date.
    """
    days_until_expiry = result["ssl_certificate"].get("days_until_expiry")

    if days_until_expiry is None:
        return

    if days_until_expiry < 0:
        result["findings"].append({
            "title": "SSL certificate is expired",
            "severity": "High",
            "evidence": f"SSL certificate expired {-days_until_expiry} day(s) ago.",
            "why": "Expired certificates break trust and may prevent users from accessing the website safely.",
            "recommendation": "Renew the SSL certificate immediately."
        })
        return

    if days_until_expiry <= 14:
        result["findings"].append({
            "title": "SSL certificate expires very soon",
            "severity": "Medium",
            "evidence": f"SSL certificate expires in {days_until_expiry} day(s).",
            "why": "A certificate close to expiry can cause downtime or browser trust warnings if not renewed in time.",
            "recommendation": "Renew or rotate the SSL certificate as soon as possible."
        })
        return

    if days_until_expiry <= 30:
        result["findings"].append({
            "title": "SSL certificate expires soon",
            "severity": "Low",
            "evidence": f"SSL certificate expires in {days_until_expiry} day(s).",
            "why": "Certificates should be renewed before expiry to avoid downtime or trust issues.",
            "recommendation": "Plan SSL certificate renewal before the expiry date."
        })