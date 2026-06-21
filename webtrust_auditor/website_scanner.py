import requests
from urllib.parse import urlparse


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


def normalize_url(url: str) -> str:
    """
    Ensures the URL has http:// or https://.
    If the user writes example.com, we convert it to https://example.com.
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
        "findings": [],
        "error": None
    }

    try:
        response = requests.get(
            normalized_url,
            timeout=30,
            allow_redirects=True,
            headers={
                "User-Agent": "WebTrust-Auditor/0.1"
            }
        )

        result["final_url"] = response.url
        result["status_code"] = response.status_code
        result["headers"] = dict(response.headers)

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

        check_security_headers(response.headers, result)

    except requests.exceptions.RequestException as error:
        result["error"] = str(error)

    return result


def check_security_headers(headers, result: dict) -> None:
    """
    Checks whether important security headers exist.
    Missing headers are added as findings.
    """
    for header_name, header_info in SECURITY_HEADERS.items():
        if header_name not in headers:
            result["findings"].append({
                "title": f"Missing {header_name}",
                "severity": header_info["severity"],
                "evidence": f"{header_name} header was not found.",
                "why": header_info["why"],
                "recommendation": f"Add the {header_name} header to improve browser-side security."
            })