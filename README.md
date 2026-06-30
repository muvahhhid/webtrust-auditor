# WebTrust Auditor

[![Tests](https://github.com/muvahhhid/webtrust-auditor/actions/workflows/tests.yml/badge.svg)](https://github.com/muvahhhid/webtrust-auditor/actions/workflows/tests.yml)

WebTrust Auditor is a defensive security readiness checker for websites, email domains and local repositories.

It helps website owners, developers and security learners identify common security hygiene issues, understand the risk and generate terminal, Markdown, JSON and PDF reports.

The tool is designed for defensive and authorized use only.

---

## Contents

* [Installation](#installation)
* [Usage](#usage)
* [Output Formats](#output-formats)
* [What It Checks](#what-it-checks)
* [Full Website Check](#full-website-check)
* [Findings, Observations and References](#findings-observations-and-references)
* [Scoring](#scoring)
* [Example Result](#example-result)
* [Project Structure](#project-structure)
* [Tests and CI](#tests-and-ci)
* [Safety Notice](#safety-notice)
* [Author](#author)

---

## Installation

Clone the repository:

```bash id="53wl9l"
git clone https://github.com/muvahhhid/webtrust-auditor.git
cd webtrust-auditor
```

Create and activate a virtual environment.

Windows PowerShell:

```powershell id="8qyij9"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash id="dv855s"
python -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash id="6aw318"
pip install -r requirements.txt
```

Check the version:

```bash id="j3q2f7"
python webtrust.py --version
```

---

## Usage

Website scan:

```bash id="8o444o"
python webtrust.py --url https://example.com
```

Owner-authorized full website check:

```bash id="rcc5fq"
python webtrust.py --url https://example.com --full-check
```

Email/domain scan:

```bash id="vq2jf3"
python webtrust.py --domain example.com
```

Email address input is supported. The domain is extracted automatically:

```bash id="i5f5ei"
python webtrust.py --domain user@example.com
```

Optional DKIM selector check:

```bash id="6ym04k"
python webtrust.py --domain example.com --dkim-selector google
```

Local repository scan:

```bash id="sqzlzw"
python webtrust.py --repo "."
```

Full website, email/domain and repository scan:

```bash id="jrb3h6"
python webtrust.py --url https://example.com --domain example.com --repo "." --full-check
```

Detailed technical explanation with OWASP and CWE references:

```bash id="99vx6h"
python webtrust.py --url https://example.com --full-check --details
```

---

## Output Formats

WebTrust Auditor supports terminal, Markdown, JSON and PDF output.

| Output   | Command option  | Best for                                             |
| -------- | --------------- | ---------------------------------------------------- |
| Terminal | default         | quick manual review                                  |
| Markdown | `--output`      | GitHub documentation and security notes              |
| JSON     | `--json-output` | automation, dashboards and integrations              |
| PDF      | `--pdf-output`  | shareable reports for clients, managers or reviewers |

Terminal only:

```bash id="ixjui8"
python webtrust.py --url https://example.com --domain example.com --repo "." --full-check
```

Markdown report:

```bash id="tx0kl0"
python webtrust.py --url https://example.com --output reports/report.md
```

JSON report:

```bash id="lot2dn"
python webtrust.py --url https://example.com --json-output reports/result.json
```

PDF report:

```bash id="z1o703"
python webtrust.py --url https://example.com --pdf-output reports/report.pdf
```

All report formats:

```bash id="0syhiu"
python webtrust.py --url https://example.com --domain example.com --repo "." --full-check --output reports/report.md --json-output reports/result.json --pdf-output reports/report.pdf
```

Generated JSON and PDF reports are ignored by Git by default.

---

## What It Checks

### Website

* HTTPS usage
* redirect and final URL
* HTTP status code
* security headers
* SSL certificate expiry
* software version disclosure in response headers

Security headers checked:

```text id="ev9p93"
Content-Security-Policy
Strict-Transport-Security
X-Frame-Options
X-Content-Type-Options
Referrer-Policy
Permissions-Policy
```

Version disclosure headers checked:

```text id="kc98g0"
Server
X-Powered-By
X-AspNet-Version
X-AspNetMvc-Version
X-Generator
```

### Email / Domain

* domain input validation
* email-to-domain normalization
* public DNS existence
* MX records
* SPF records
* DMARC record and policy
* optional DKIM selector

### Repository

* `.gitignore`
* `README.md`
* Dockerfile and `.dockerignore` relationship
* sensitive file names
* sensitive file extensions
* hardcoded secret-like assignments
* GitHub token patterns
* AWS key patterns
* private key blocks
* JWT-like tokens

---

## Full Website Check

`--full-check` enables a deeper website review for websites you own or are authorized to test.

It uses a fixed curated list of low-impact GET-only checks for common public exposure risks.

Checked categories include:

* exposed environment files
* exposed configuration files
* exposed Git metadata
* backup archives
* database dumps
* debug or server information pages
* public source maps
* public dependency/package files
* security contact metadata

Example checked paths:

```text id="qfjm61"
/.env
/.env.production
/.git/config
/.git/HEAD
/phpinfo.php
/server-status
/backup.zip
/database.sql
/appsettings.json
/web.config
/package.json
/.well-known/security.txt
```

Full check mode does not perform directory brute-forcing, crawling, fuzzing, POST requests, form submission, exploitation, authentication bypass or destructive actions.

Use this option only on websites you own or are authorized to test.

---

## Findings, Observations and References

WebTrust Auditor separates security findings from observations.

### Findings

Findings are security issues or weaknesses that affect the score.

Examples:

```text id="td5uxz"
Missing Permissions-Policy
DMARC record is missing
Exposed environment file: /.env
Exposed Git repository file: /.git/config
Possible GitHub token found
```

### Observations

Observations are useful notes that do not reduce the score.

Examples:

```text id="2edvll"
DKIM check skipped because no selector was provided
robots.txt was found
security.txt was not found
Full website check mode was enabled
146 fixed paths were tested
```

### References

Findings are enriched with professional security references where applicable:

* OWASP Top 10 categories
* CWE weakness identifiers
* official reference URLs

Example:

```text id="0s3w42"
Finding: Missing Permissions-Policy
Category: Browser Security Hardening
OWASP: OWASP Top 10 A05:2021 - Security Misconfiguration
CWE: CWE-693 - Protection Mechanism Failure
```

Example:

```text id="157sqp"
Finding: Possible GitHub token found
Category: Exposed Secret
OWASP: OWASP Top 10 A07:2021 - Identification and Authentication Failures
CWE: CWE-798 - Use of Hard-coded Credentials
```

---

## Scoring

Each scanned component receives a score from 0 to 100.

| Severity | Penalty |
| -------- | ------: |
| High     |     -25 |
| Medium   |     -10 |
| Low      |      -5 |
| Info     |       0 |

|  Score | Rating |
| -----: | ------ |
| 90-100 | A      |
|  75-89 | B      |
|  60-74 | C      |
|  40-59 | D      |
|   0-39 | F      |

Observations do not reduce the score.

---

## Example Result

Example command:

```bash id="ouq7z6"
python webtrust.py --url https://github.com --domain github.com --repo "." --full-check
```

Example summary:

| Component      |     Score | Rating | Findings | Status |
| -------------- | --------: | ------ | -------: | ------ |
| Website        |  95 / 100 | A      |        1 | Good   |
| Email / Domain | 100 / 100 | A      |        0 | Good   |
| Repository     | 100 / 100 | A      |        0 | Good   |

---

## Project Structure

```text id="kugxhv"
webtrust-auditor/
├── .github/
│   └── workflows/
│       └── tests.yml
├── reports/
│   └── github-final-full-report.md
├── tests/
│   ├── test_email_scanner.py
│   ├── test_references.py
│   ├── test_repo_scanner.py
│   ├── test_scoring.py
│   ├── test_website_full_check.py
│   └── test_website_scanner.py
├── webtrust_auditor/
│   ├── __init__.py
│   ├── cli.py
│   ├── email_scanner.py
│   ├── pdf_generator.py
│   ├── references.py
│   ├── report_generator.py
│   ├── repo_scanner.py
│   ├── scoring.py
│   └── website_scanner.py
├── .gitignore
├── README.md
├── requirements.txt
└── webtrust.py
```

---

## Tests and CI

Run tests locally:

```bash id="g8ttba"
python -m pytest
```

The test suite covers:

* scoring logic
* website scanner helpers
* full website check detection logic
* email/domain normalization
* DMARC policy extraction
* repository hygiene checks
* secret pattern detection
* OWASP/CWE reference mapping

GitHub Actions runs tests automatically on push and pull requests.

Workflow file:

```text id="eb1ji4"
.github/workflows/tests.yml
```

---

## Safety Notice

WebTrust Auditor is intended for defensive security review, learning and authorized assessments.

Default website checks are basic readiness checks.

Full website checks are intended only for websites you own or are authorized to test.

The tool does not:

* exploit vulnerabilities
* brute-force directories
* crawl websites
* fuzz parameters
* bypass authentication
* submit forms
* send POST requests
* upload files
* modify remote systems
* perform destructive actions

Website checks use normal HTTP GET requests.

Email/domain checks use public DNS records.

Repository checks read local project files.

---

## Author

Created by Muvahhhid

---

## License

This project is intended for educational and defensive security purposes.
