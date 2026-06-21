# WebTrust Auditor

WebTrust Auditor is a defensive security readiness checker for websites, email domains, and local project repositories.

The tool performs passive checks only. It does not attack, exploit, brute-force, send emails, upload files, or modify the target system.

## Purpose

WebTrust Auditor helps developers, students, and small teams review whether a public website, email domain, or GitHub project is ready to be shown publicly.

It focuses on practical defensive security checks, clear findings, simple scoring, and Markdown report generation.

## Features

### Website Security Checks

WebTrust Auditor checks:

* HTTPS usage
* Final URL after redirects
* HTTP status code
* Security headers:

  * Content-Security-Policy
  * Strict-Transport-Security
  * X-Frame-Options
  * X-Content-Type-Options
  * Referrer-Policy
  * Permissions-Policy

### Email / Domain Security Checks

WebTrust Auditor checks public DNS records for:

* MX records
* SPF records
* DMARC record
* DMARC policy
* Optional DKIM selector check

### Repository Hygiene Checks

WebTrust Auditor checks a local project folder for:

* `.gitignore`
* `README.md`
* `Dockerfile`
* `.dockerignore`
* Sensitive files such as `.env` or `secrets.json`
* Database files such as `.db`, `.sqlite`, `.db-wal`, `.db-shm`
* Potential hardcoded secret assignments
* Recommended `.gitignore` rules

## Security Scoring

Each scan result receives a simple readiness score.

Severity penalties:

| Severity | Penalty |
| -------- | ------: |
| High     |     -25 |
| Medium   |     -10 |
| Low      |      -5 |
| Info     |      -0 |

Ratings:

|  Score | Rating |
| -----: | ------ |
| 90–100 | A      |
|  75–89 | B      |
|  60–74 | C      |
|  40–59 | D      |
|   0–39 | F      |

## Requirements

* Python 3.10 or newer
* pip

## Installation

Clone the repository:

```bash
git clone https://github.com/muvahhhid/webtrust-auditor.git
cd webtrust-auditor
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate the virtual environment.

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

On macOS/Linux:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Website Scan

```bash
python webtrust.py --url https://github.com
```

### Email / Domain Scan

```bash
python webtrust.py --domain github.com
```

### Repository Hygiene Scan

On Windows:

```powershell
python webtrust.py --repo "C:\Users\user\Desktop\webtrust-auditor"
```

### Full Scan

```powershell
python webtrust.py --url https://github.com --domain github.com --repo "C:\Users\user\Desktop\webtrust-auditor" --output reports/github-final-full-report.md
```

## Example Report

A sample report is included in the `reports` folder:

```text
reports/github-final-full-report.md
```

The sample report includes:

* Scan information
* Website security results
* Email/domain security results
* Repository hygiene results
* Security scores
* Findings overview
* Score deductions
* Detailed explanations
* Recommendations

## Example Result

```text
Website Security Score: 95 / 100
Email Domain Security Score: 100 / 100
Repository Hygiene Score: 100 / 100
```

## Project Structure

```text
webtrust-auditor/
├── webtrust.py
├── requirements.txt
├── README.md
├── .gitignore
├── reports/
│   └── github-final-full-report.md
└── webtrust_auditor/
    ├── __init__.py
    ├── cli.py
    ├── website_scanner.py
    ├── email_scanner.py
    ├── repo_scanner.py
    ├── scoring.py
    └── report_generator.py
```

## Safety Notice

WebTrust Auditor is a defensive security tool.

It only performs passive checks such as:

* Reading HTTP response headers
* Reading public DNS records
* Reading local repository files
* Generating local Markdown reports

It does not:

* Exploit vulnerabilities
* Run attacks
* Brute-force credentials
* Send phishing emails
* Modify target systems
* Upload local files

## Skills Demonstrated

This project demonstrates practical knowledge in:

* Python development
* Command-line interface design
* HTTP security headers
* DNS and email security basics
* SPF, DMARC, MX, and DKIM concepts
* Repository hygiene checks
* Secret detection logic
* Security scoring
* Markdown report generation
* Defensive cybersecurity tooling

## Author

Created by Muvahhhid

This project is intended for educational and defensive security purposes.
