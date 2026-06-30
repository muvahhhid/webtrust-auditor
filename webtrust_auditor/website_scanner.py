import difflib
import re
import socket
import ssl
import uuid
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests


SECURITY_HEADERS = {
    "content-security-policy": {
        "display_name": "Content-Security-Policy",
        "severity": "Medium",
        "recommendation": "Add a Content-Security-Policy header to reduce XSS and content injection risks.",
    },
    "strict-transport-security": {
        "display_name": "Strict-Transport-Security",
        "severity": "Medium",
        "recommendation": "Add the Strict-Transport-Security header after confirming HTTPS is correctly configured.",
    },
    "x-frame-options": {
        "display_name": "X-Frame-Options",
        "severity": "Low",
        "recommendation": "Add X-Frame-Options or use CSP frame-ancestors to reduce clickjacking risk.",
    },
    "x-content-type-options": {
        "display_name": "X-Content-Type-Options",
        "severity": "Low",
        "recommendation": "Add X-Content-Type-Options: nosniff.",
    },
    "referrer-policy": {
        "display_name": "Referrer-Policy",
        "severity": "Low",
        "recommendation": "Add a Referrer-Policy header to control how referrer data is shared.",
    },
    "permissions-policy": {
        "display_name": "Permissions-Policy",
        "severity": "Low",
        "recommendation": "Add the Permissions-Policy header to improve browser-side security.",
    },
}


VERSION_DISCLOSURE_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
]


VERSION_PATTERN = re.compile(r"\b\d+(?:\.\d+){1,4}\b")


REQUEST_TIMEOUT_SECONDS = 5
MAX_BODY_SAMPLE_BYTES = 8192


def scan_website(url: str, full_check: bool = False) -> dict:
    """
    Scans website security posture.

    Default mode performs basic website checks.

    Full check mode performs additional owner-authorized, low-impact,
    GET-only exposure checks against a fixed curated path list.
    It does not brute-force directories, fuzz parameters, submit forms,
    bypass authentication or exploit vulnerabilities.
    """
    normalized_url = normalize_url(url)

    result = {
        "target_url": normalized_url,
        "final_url": None,
        "status_code": None,
        "https": False,
        "uses_https": False,
        "headers": {},
        "headers_lower": {},
        "ssl": {
            "checked": False,
            "not_before": None,
            "not_after": None,
            "days_until_expiry": None,
            "issuer": None,
            "subject": None,
            "error": None,
        },
        "ssl_certificate": None,
        "full_check_enabled": full_check,
        "full_check_paths_tested": 0,
        "full_check_results": [],
        "observations": [],
        "findings": [],
        "error": None,
    }

    try:
        response = requests.get(
            normalized_url,
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=True,
            headers={"User-Agent": "WebTrustAuditor/1.7.0"},
        )
    except requests.RequestException as exc:
        result["error"] = str(exc)
        result["findings"].append(
            {
                "title": "Website request failed",
                "severity": "High",
                "evidence": str(exc),
                "why": "The website could not be reached, so website security checks could not be completed.",
                "recommendation": "Verify that the URL is correct and that the website is reachable.",
            }
        )
        return result

    result["final_url"] = response.url
    result["status_code"] = response.status_code
    result["headers"] = dict(response.headers)
    result["headers_lower"] = normalize_headers(response.headers)
    result["https"] = response.url.lower().startswith("https://")
    result["uses_https"] = result["https"]

    if not result["https"]:
        result["findings"].append(
            {
                "title": "Website is not using HTTPS",
                "severity": "High",
                "evidence": f"Final URL is {response.url}.",
                "why": "Without HTTPS, data can be transmitted in cleartext and users may be exposed to interception.",
                "recommendation": "Enable HTTPS and redirect HTTP traffic to HTTPS.",
            }
        )

    check_security_headers(result)
    check_version_disclosure(result)

    ssl_result = check_ssl_certificate(response.url)
    result["ssl"] = ssl_result
    result["ssl_certificate"] = ssl_result
    add_ssl_findings(result, ssl_result)

    if full_check:
        result["observations"].append(
            {
                "title": "Full website check enabled",
                "details": (
                    "Fixed GET-only checklist was used. No brute-force, crawling, fuzzing or exploitation."
                ),
            }
        )

        full_check_result = perform_full_check(response.url)
        result["full_check_paths_tested"] = full_check_result["paths_tested"]
        result["full_check_results"] = full_check_result["checked_paths"]
        result["findings"].extend(full_check_result["findings"])
        result["observations"].extend(full_check_result["observations"])

    return result


def normalize_url(url: str) -> str:
    """
    Adds https:// when the user provides a bare domain.
    """
    cleaned_url = url.strip()

    if not cleaned_url.startswith(("http://", "https://")):
        cleaned_url = f"https://{cleaned_url}"

    return cleaned_url


def normalize_headers(headers: dict) -> dict:
    """
    Converts response header names to lowercase for case-insensitive checks.
    """
    return {str(key).lower(): value for key, value in dict(headers).items()}


def check_security_headers(result: dict) -> None:
    headers_lower = result["headers_lower"]

    for header_name, header_data in SECURITY_HEADERS.items():
        if header_name not in headers_lower:
            result["findings"].append(
                {
                    "title": f"Missing {header_data['display_name']}",
                    "severity": header_data["severity"],
                    "evidence": f"The {header_data['display_name']} header was not found in the HTTP response.",
                    "why": "Security headers help browsers enforce safer behavior and reduce common client-side risks.",
                    "recommendation": header_data["recommendation"],
                }
            )


def check_version_disclosure(result: dict) -> None:
    headers_lower = result["headers_lower"]

    for header_name in VERSION_DISCLOSURE_HEADERS:
        header_value = headers_lower.get(header_name)

        if not header_value:
            continue

        if contains_version_number(header_value):
            result["findings"].append(
                {
                    "title": "Software version disclosure detected",
                    "severity": "Low",
                    "evidence": f"{header_name}: {header_value}",
                    "why": (
                        "Exposing exact software versions can help attackers search for known vulnerabilities "
                        "affecting that specific version."
                    ),
                    "recommendation": "Avoid exposing exact software versions in public response headers.",
                }
            )


def contains_version_number(value: str) -> bool:
    """
    Detects version-like numbers such as 2.4.49 or 8.3.4.
    """
    return VERSION_PATTERN.search(value or "") is not None


def has_version_number(value: str) -> bool:
    """
    Backward-compatible alias used by tests or older code.
    """
    return contains_version_number(value)


def check_ssl_certificate(url: str) -> dict:
    parsed_url = urlparse(url)

    result = {
        "checked": False,
        "not_before": None,
        "not_after": None,
        "days_until_expiry": None,
        "issuer": None,
        "subject": None,
        "error": None,
    }

    if parsed_url.scheme != "https":
        result["error"] = "SSL certificate check skipped because the final URL is not HTTPS."
        return result

    hostname = parsed_url.hostname

    if not hostname:
        result["error"] = "SSL certificate check failed because no hostname was found."
        return result

    port = parsed_url.port or 443

    try:
        context = ssl.create_default_context()

        with socket.create_connection((hostname, port), timeout=REQUEST_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                certificate = secure_sock.getpeercert()

        not_before = parse_ssl_datetime(certificate.get("notBefore"))
        not_after = parse_ssl_datetime(certificate.get("notAfter"))

        result["checked"] = True
        result["not_before"] = format_datetime(not_before)
        result["not_after"] = format_datetime(not_after)
        result["days_until_expiry"] = (not_after - datetime.now(timezone.utc)).days
        result["issuer"] = certificate.get("issuer")
        result["subject"] = certificate.get("subject")

    except Exception as exc:
        result["error"] = str(exc)

    return result


def parse_ssl_datetime(value: str) -> datetime:
    parsed_value = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
    return parsed_value.replace(tzinfo=timezone.utc)


def format_datetime(value: datetime | None) -> str | None:
    if not value:
        return None

    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def add_ssl_findings(result: dict, ssl_result: dict) -> None:
    if not ssl_result.get("checked"):
        return

    days_until_expiry = ssl_result.get("days_until_expiry")

    if days_until_expiry is None:
        return

    if days_until_expiry < 0:
        result["findings"].append(
            {
                "title": "SSL certificate has expired",
                "severity": "High",
                "evidence": f"Certificate expired on {ssl_result.get('not_after')}.",
                "why": "Expired certificates cause browser warnings and can break user trust.",
                "recommendation": "Renew the SSL certificate immediately.",
            }
        )
    elif days_until_expiry <= 14:
        result["findings"].append(
            {
                "title": "SSL certificate expires very soon",
                "severity": "Medium",
                "evidence": f"Certificate expires on {ssl_result.get('not_after')} ({days_until_expiry} days left).",
                "why": "Certificates that expire soon can cause downtime or browser warnings if not renewed in time.",
                "recommendation": "Renew the SSL certificate before it expires.",
            }
        )
    elif days_until_expiry <= 30:
        result["findings"].append(
            {
                "title": "SSL certificate expires soon",
                "severity": "Low",
                "evidence": f"Certificate expires on {ssl_result.get('not_after')} ({days_until_expiry} days left).",
                "why": "The certificate is still valid, but renewal should be planned.",
                "recommendation": "Plan SSL certificate renewal.",
            }
        )


def perform_full_check(base_url: str) -> dict:
    """
    Performs owner-authorized full website check.

    This is not a directory brute-force.
    It checks a fixed curated list of high-risk public exposure paths.
    """
    targets = build_full_check_targets()

    result = {
        "paths_tested": 0,
        "checked_paths": [],
        "findings": [],
        "observations": [],
    }

    baseline_path = f"/.webtrust-auditor-baseline-{uuid.uuid4().hex}"
    baseline_response = fetch_path(base_url, baseline_path)

    for target in targets:
        response_info = fetch_path(base_url, target["path"])
        result["paths_tested"] += 1

        result["checked_paths"].append(
            {
                "path": target["path"],
                "status_code": response_info.get("status_code"),
                "content_type": response_info.get("content_type"),
                "category": target["category"],
            }
        )

        if target.get("observation_only"):
            observation = build_observation_for_target(target, response_info)

            if observation:
                result["observations"].append(observation)

            continue

        if is_full_check_exposure(target, response_info, baseline_response):
            result["findings"].append(
                {
                    "title": target["title"],
                    "severity": target["severity"],
                    "evidence": (
                        f"{response_info.get('url')} returned HTTP {response_info.get('status_code')} "
                        f"with content type {response_info.get('content_type') or 'unknown'}."
                    ),
                    "why": target["why"],
                    "recommendation": target["recommendation"],
                }
            )

    result["observations"].append(
        {
            "title": "Full check paths tested",
            "details": f"{result['paths_tested']} fixed low-impact GET-only paths were checked.",
        }
    )

    return result


def build_full_check_targets() -> list[dict]:
    targets = []

    def add(path: str, title: str, severity: str, category: str, why: str, recommendation: str, validator: str):
        targets.append(
            {
                "path": path,
                "title": title,
                "severity": severity,
                "category": category,
                "why": why,
                "recommendation": recommendation,
                "validator": validator,
            }
        )

    def add_observation(path: str, title: str, category: str, found_message: str, missing_message: str):
        targets.append(
            {
                "path": path,
                "title": title,
                "category": category,
                "observation_only": True,
                "found_message": found_message,
                "missing_message": missing_message,
            }
        )

    env_paths = [
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.env.prod",
        "/.env.development",
        "/.env.dev",
        "/.env.stage",
        "/.env.staging",
        "/.env.test",
        "/.env.backup",
        "/.env.bak",
        "/.env.old",
        "/api/.env",
        "/app/.env",
        "/backend/.env",
        "/server/.env",
    ]

    for path in env_paths:
        add(
            path=path,
            title=f"Exposed environment file: {path}",
            severity="High",
            category="Exposed Sensitive Configuration",
            why="Environment files often contain database passwords, API keys, tokens and application secrets.",
            recommendation="Remove the file from the public web root and rotate any exposed credentials.",
            validator="env",
        )

    git_paths = [
        "/.git/config",
        "/.git/HEAD",
        "/.git/index",
        "/.git/logs/HEAD",
        "/.git/packed-refs",
    ]

    for path in git_paths:
        add(
            path=path,
            title=f"Exposed Git repository file: {path}",
            severity="High",
            category="Source Code Exposure",
            why="Publicly exposed .git files may allow attackers to reconstruct source code or discover internal repository data.",
            recommendation="Block public access to .git paths and ensure source control metadata is not deployed to the web root.",
            validator="git",
        )

    config_paths = [
        "/config.php",
        "/config.json",
        "/config.yml",
        "/config.yaml",
        "/configuration.php",
        "/settings.php",
        "/settings.py",
        "/local_settings.py",
        "/appsettings.json",
        "/appsettings.Development.json",
        "/appsettings.Production.json",
        "/web.config",
        "/Web.config",
        "/application.yml",
        "/application.yaml",
        "/application.properties",
        "/bootstrap.yml",
        "/bootstrap.properties",
        "/database.php",
        "/db.php",
        "/connect.php",
        "/connection.php",
        "/wp-config.php",
        "/sites/default/settings.php",
        "/.npmrc",
        "/.pypirc",
        "/.dockercfg",
        "/docker-compose.yml",
        "/docker-compose.yaml",
    ]

    for path in config_paths:
        add(
            path=path,
            title=f"Exposed configuration file: {path}",
            severity="High",
            category="Exposed Sensitive Configuration",
            why="Configuration files may contain credentials, connection strings, internal endpoints or deployment secrets.",
            recommendation="Remove sensitive configuration files from the public web root and rotate any exposed credentials.",
            validator="config",
        )

    backup_paths = [
        "/backup.zip",
        "/backup.tar",
        "/backup.tar.gz",
        "/backup.tgz",
        "/backup.7z",
        "/backup.rar",
        "/site.zip",
        "/site.tar.gz",
        "/www.zip",
        "/www.tar.gz",
        "/public.zip",
        "/public_html.zip",
        "/html.zip",
        "/app.zip",
        "/src.zip",
        "/source.zip",
        "/code.zip",
        "/website.zip",
        "/old.zip",
        "/old.tar.gz",
        "/new.zip",
        "/prod.zip",
        "/production.zip",
        "/staging.zip",
        "/dev.zip",
        "/test.zip",
        "/backup.bak",
        "/site.bak",
        "/www.bak",
        "/database.bak",
    ]

    for path in backup_paths:
        add(
            path=path,
            title=f"Exposed backup archive or backup file: {path}",
            severity="High",
            category="Exposed Backup or Database Dump",
            why="Backup archives may contain source code, credentials, database dumps or internal configuration files.",
            recommendation="Remove public backup files and store backups outside the web root with proper access control.",
            validator="backup",
        )

    database_paths = [
        "/database.sql",
        "/db.sql",
        "/dump.sql",
        "/backup.sql",
        "/db_backup.sql",
        "/database_backup.sql",
        "/mysql.sql",
        "/postgres.sql",
        "/data.sql",
        "/export.sql",
        "/site.sql",
        "/users.sql",
        "/backup/database.sql",
        "/backup/db.sql",
        "/db.sqlite",
        "/database.sqlite",
        "/database.sqlite3",
        "/app.db",
        "/data.db",
    ]

    for path in database_paths:
        add(
            path=path,
            title=f"Exposed database dump or database file: {path}",
            severity="High",
            category="Exposed Backup or Database Dump",
            why="Database dumps and database files may expose user data, credentials, tokens and business information.",
            recommendation="Remove database dumps from the public web root and rotate any credentials found inside them.",
            validator="database",
        )

    debug_paths = [
        "/phpinfo.php",
        "/info.php",
        "/test.php",
        "/debug.php",
        "/debug",
        "/server-status",
        "/server-info",
        "/actuator",
        "/actuator/env",
        "/actuator/health",
        "/actuator/configprops",
        "/actuator/beans",
        "/_profiler",
        "/_debugbar",
        "/laravel-debugbar",
    ]

    for path in debug_paths:
        add(
            path=path,
            title=f"Public debug or server information page: {path}",
            severity="Medium",
            category="Information Disclosure",
            why="Debug and server information pages may reveal versions, environment values, internal paths or framework details.",
            recommendation="Disable public debug pages and restrict server information endpoints to authorized users only.",
            validator="debug",
        )

    source_map_paths = [
        "/app.js.map",
        "/main.js.map",
        "/bundle.js.map",
        "/vendor.js.map",
        "/runtime.js.map",
        "/static/js/main.js.map",
        "/static/js/bundle.js.map",
        "/assets/app.js.map",
        "/assets/main.js.map",
        "/js/app.js.map",
        "/js/main.js.map",
        "/dist/app.js.map",
        "/dist/main.js.map",
    ]

    for path in source_map_paths:
        add(
            path=path,
            title=f"Public JavaScript source map: {path}",
            severity="Low",
            category="Information Disclosure",
            why="Source maps may expose frontend source code, internal file names, comments and application structure.",
            recommendation="Avoid publishing source maps in production unless they are intentionally public.",
            validator="sourcemap",
        )

    dependency_paths = [
        "/package.json",
        "/package-lock.json",
        "/yarn.lock",
        "/pnpm-lock.yaml",
        "/composer.json",
        "/composer.lock",
        "/requirements.txt",
        "/Pipfile",
        "/Pipfile.lock",
        "/poetry.lock",
        "/pom.xml",
        "/build.gradle",
        "/Gemfile",
        "/Gemfile.lock",
        "/go.mod",
        "/go.sum",
    ]

    for path in dependency_paths:
        add(
            path=path,
            title=f"Public dependency or package file: {path}",
            severity="Low",
            category="Information Disclosure",
            why="Dependency files may reveal technology stacks and package versions that can help vulnerability research.",
            recommendation="Avoid exposing dependency files publicly unless they are intentionally published.",
            validator="dependency",
        )

    add_observation(
        path="/robots.txt",
        title="robots.txt check",
        category="Public Metadata",
        found_message="Found. Review for sensitive internal paths.",
        missing_message="Not found.",
    )

    add_observation(
        path="/security.txt",
        title="security.txt check",
        category="Security Contact Metadata",
        found_message="Found.",
        missing_message="Not found. Consider adding /.well-known/security.txt.",
    )

    add_observation(
        path="/.well-known/security.txt",
        title=".well-known/security.txt check",
        category="Security Contact Metadata",
        found_message="Found.",
        missing_message="Not found. Consider adding it for security contact info.",
    )

    return targets


def fetch_path(base_url: str, path: str) -> dict:
    absolute_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

    response_info = {
        "url": absolute_url,
        "path": path,
        "status_code": None,
        "content_type": None,
        "content_length": None,
        "body_sample": b"",
        "body_text": "",
        "error": None,
    }

    try:
        response = requests.get(
            absolute_url,
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=True,
            stream=True,
            headers={
                "User-Agent": "WebTrustAuditor/1.7.0",
            },
        )

        response_info["status_code"] = response.status_code
        response_info["content_type"] = response.headers.get("Content-Type", "")
        response_info["content_length"] = response.headers.get("Content-Length")

        sample = b""

        for chunk in response.iter_content(chunk_size=MAX_BODY_SAMPLE_BYTES):
            sample += chunk

            if len(sample) >= MAX_BODY_SAMPLE_BYTES:
                sample = sample[:MAX_BODY_SAMPLE_BYTES]
                break

        response.close()

        response_info["body_sample"] = sample
        response_info["body_text"] = sample.decode("utf-8", errors="ignore")

    except requests.RequestException as exc:
        response_info["error"] = str(exc)

    return response_info


def is_full_check_exposure(target: dict, response_info: dict, baseline_response: dict | None = None) -> bool:
    status_code = response_info.get("status_code")

    if status_code not in (200, 206):
        return False

    if looks_like_baseline_response(response_info, baseline_response):
        return False

    validator_name = target.get("validator")

    validators = {
        "env": is_env_exposure,
        "git": is_git_exposure,
        "config": is_config_exposure,
        "backup": is_backup_exposure,
        "database": is_database_exposure,
        "debug": is_debug_exposure,
        "sourcemap": is_sourcemap_exposure,
        "dependency": is_dependency_exposure,
    }

    validator = validators.get(validator_name)

    if not validator:
        return False

    return validator(response_info, target)


def looks_like_baseline_response(response_info: dict, baseline_response: dict | None) -> bool:
    if not baseline_response:
        return False

    if baseline_response.get("status_code") not in (200, 206):
        return False

    if response_info.get("status_code") != baseline_response.get("status_code"):
        return False

    content_type = (response_info.get("content_type") or "").lower()

    if "text/html" not in content_type:
        return False

    current_text = response_info.get("body_text") or ""
    baseline_text = baseline_response.get("body_text") or ""

    if not current_text or not baseline_text:
        return False

    similarity = difflib.SequenceMatcher(None, current_text[:2000], baseline_text[:2000]).ratio()

    return similarity > 0.90


def is_env_exposure(response_info: dict, target: dict) -> bool:
    text = response_info.get("body_text", "")

    if len(text.strip()) < 8:
        return False

    indicators = [
        "APP_KEY=",
        "APP_SECRET=",
        "DB_PASSWORD=",
        "DB_USERNAME=",
        "DB_HOST=",
        "DATABASE_URL=",
        "SECRET_KEY=",
        "API" + "_KEY=",
        "ACCESS" + "_TOKEN=",
        "JWT_SECRET=",
        "MAIL_PASSWORD=",
    ]

    upper_text = text.upper()

    return any(indicator in upper_text for indicator in indicators)


def is_git_exposure(response_info: dict, target: dict) -> bool:
    path = target.get("path", "")
    text = response_info.get("body_text", "")

    if path.endswith("/config"):
        return "[core]" in text and "repositoryformatversion" in text.lower()

    if path.endswith("/HEAD"):
        return text.startswith("ref: refs/")

    if path.endswith("/logs/HEAD"):
        return "commit:" in text.lower() or "checkout:" in text.lower()

    if path.endswith("/packed-refs"):
        return "refs/" in text

    if path.endswith("/index"):
        sample = response_info.get("body_sample", b"")
        return sample.startswith(b"DIRC")

    return False


def is_config_exposure(response_info: dict, target: dict) -> bool:
    path = target.get("path", "").lower()
    text = response_info.get("body_text", "")
    lower_text = text.lower()

    if len(text.strip()) < 10:
        return False

    sensitive_keywords = [
        "password",
        "passwd",
        "secret",
        "api" + "_key",
        "api" + "key",
        "token",
        "connectionstring",
        "connectionstrings",
        "database_url",
        "db_password",
        "private_key",
        "client_secret",
    ]

    if any(keyword in lower_text for keyword in sensitive_keywords):
        return True

    if path.endswith((".json", ".yml", ".yaml", ".properties", ".php", ".py", ".config")):
        structure_indicators = ["{", "}", "=", ":", "<?php", "django", "spring", "connectionstrings"]
        return any(indicator in lower_text for indicator in structure_indicators)

    return False


def is_backup_exposure(response_info: dict, target: dict) -> bool:
    sample = response_info.get("body_sample", b"")
    content_type = (response_info.get("content_type") or "").lower()
    path = target.get("path", "").lower()

    archive_signatures = [
        sample.startswith(b"PK"),
        sample.startswith(b"\x1f\x8b"),
        sample.startswith(b"Rar!"),
        sample.startswith(b"7z"),
        "application/zip" in content_type,
        "application/x-gzip" in content_type,
        "application/octet-stream" in content_type and path.endswith((".zip", ".gz", ".tar", ".rar", ".7z", ".bak")),
    ]

    return any(archive_signatures)


def is_database_exposure(response_info: dict, target: dict) -> bool:
    text = response_info.get("body_text", "")
    lower_text = text.lower()
    sample = response_info.get("body_sample", b"")
    path = target.get("path", "").lower()

    sql_indicators = [
        "create table",
        "insert into",
        "drop table",
        "mysql dump",
        "postgresql database dump",
        "sqlite format",
        "dump completed",
    ]

    if any(indicator in lower_text for indicator in sql_indicators):
        return True

    if path.endswith((".sqlite", ".sqlite3", ".db")) and sample.startswith(b"SQLite format 3"):
        return True

    return False


def is_debug_exposure(response_info: dict, target: dict) -> bool:
    text = response_info.get("body_text", "")
    lower_text = text.lower()
    path = target.get("path", "").lower()
    content_type = (response_info.get("content_type") or "").lower()

    if len(text.strip()) < 30:
        return False

    if path in ["/phpinfo.php", "/info.php"]:
        return (
            "phpinfo()" in lower_text
            or "php version" in lower_text
            or "configuration" in lower_text and "php core" in lower_text
        )

    if path in ["/server-status", "/server-info"]:
        strong_server_markers = [
            "apache server status",
            "server uptime",
            "total accesses",
            "cpu usage",
            "apache server information",
            "server settings",
        ]

        return any(marker in lower_text for marker in strong_server_markers)

    if path.startswith("/actuator"):
        if "application/json" not in content_type and not lower_text.strip().startswith("{"):
            return False

        actuator_markers = [
            '"_links"',
            '"health"',
            '"beans"',
            '"env"',
            '"configprops"',
            '"spring"',
            '"status"',
        ]

        return any(marker in lower_text for marker in actuator_markers)

    if path in ["/_profiler", "/_debugbar", "/laravel-debugbar"]:
        debug_markers = [
            "symfony profiler",
            "web debug toolbar",
            "laravel debugbar",
            "debugbar",
            "queries",
            "route",
            "middleware",
        ]

        return any(marker in lower_text for marker in debug_markers)

    if path in ["/debug", "/debug.php", "/test.php"]:
        generic_debug_markers = [
            "debug mode",
            "debug toolbar",
            "stack trace",
            "traceback",
            "exception",
            "environment variables",
            "application debug",
        ]

        return any(marker in lower_text for marker in generic_debug_markers)

    return False

def is_sourcemap_exposure(response_info: dict, target: dict) -> bool:
    text = response_info.get("body_text", "")
    lower_text = text.lower()

    return '"version"' in lower_text and '"sources"' in lower_text and '"mappings"' in lower_text


def is_dependency_exposure(response_info: dict, target: dict) -> bool:
    text = response_info.get("body_text", "")
    lower_text = text.lower()
    path = target.get("path", "").lower()

    if len(text.strip()) < 10:
        return False

    package_indicators = {
        "package.json": ['"dependencies"', '"scripts"', '"devdependencies"'],
        "composer.json": ['"require"', '"autoload"'],
        "requirements.txt": ["==", ">=", "django", "flask", "requests"],
        "pom.xml": ["<project", "<dependencies", "<artifactid"],
        "build.gradle": ["plugins", "dependencies", "implementation"],
        "gemfile": ["source ", "gem "],
        "go.mod": ["module ", "require "],
    }

    for file_name, indicators in package_indicators.items():
        if file_name in path:
            return any(indicator in lower_text for indicator in indicators)

    lock_file_names = [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "composer.lock",
        "pipfile.lock",
        "poetry.lock",
        "gemfile.lock",
        "go.sum",
    ]

    return any(file_name in path for file_name in lock_file_names)


def build_observation_for_target(target: dict, response_info: dict) -> dict | None:
    status_code = response_info.get("status_code")

    if status_code in (200, 206):
        details = target.get("found_message")
    else:
        details = target.get("missing_message")

    if not details:
        return None

    return {
        "title": target["title"],
        "details": details,
    }