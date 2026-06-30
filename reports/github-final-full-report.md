# WebTrust Auditor Report

Generated at: `2026-06-30T14:25:31.170228Z`
Tool version: `v1.7.0`

> WebTrust Auditor is a defensive security readiness checker. Full website checks, when enabled, use a fixed curated list of low-impact GET-only checks and must only be used on websites you own or are authorized to test.

## Executive Summary

| Component | Score | Rating | Findings | Observations | Status |
|---|---:|---|---:|---:|---|
| Website | 95 / 100 | A | 1 | 5 | Good |
| Email / Domain | 100 / 100 | A | 0 | 1 | Good |
| Repository | 100 / 100 | A | 0 | 0 | Good |

## Website Security

| Item | Value |
|---|---|
| Target URL | `https://github.com` |
| Final URL | `https://github.com/` |
| Status Code | `200` |
| HTTPS | Yes |
| SSL Expires | `2026-08-02 23:59:59 UTC` (33 days left) |
| Full Check | Enabled |
| Paths Tested | `146` |

### Score

| Score | Rating | High | Medium | Low | Info |
|---:|---|---:|---:|---:|---:|
| 95 / 100 | A | 0 | 0 | 1 | 0 |

### Findings

#### 1. Missing Permissions-Policy

- **Severity:** Low
- **Category:** Browser Security Hardening
- **Evidence:** The Permissions-Policy header was not found in the HTTP response.
- **Why it matters:** Security headers help browsers enforce safer behavior and reduce common client-side risks.
- **Recommendation:** Add the Permissions-Policy header to improve browser-side security.
- **OWASP:** OWASP Top 10 A05:2021 - Security Misconfiguration
- **CWE:** CWE-693 - Protection Mechanism Failure
- **References:**
  - https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
  - https://cwe.mitre.org/data/definitions/693.html

### Observations

| Observation | Details |
|---|---|
| Full website check enabled | Fixed GET-only checklist was used. No brute-force, crawling, fuzzing or exploitation. |
| robots.txt check | Found. Review for sensitive internal paths. |
| security.txt check | Not found. Consider adding /.well-known/security.txt. |
| .well-known/security.txt check | Found. |
| Full check paths tested | 146 fixed low-impact GET-only paths were checked. |

## Email / Domain Security

| Item | Value |
|---|---|
| Domain | `github.com` |
| MX Records | `1` |
| SPF Records | `1` |
| DMARC Record | Yes |
| DMARC Policy | `quarantine` |
| DKIM Selector | `N/A` |
| DKIM Record | No |

### Score

| Score | Rating | High | Medium | Low | Info |
|---:|---|---:|---:|---:|---:|
| 100 / 100 | A | 0 | 0 | 0 | 0 |

### Findings

No security findings found.

### Observations

| Observation | Details |
|---|---|
| DKIM check skipped | No DKIM selector was provided. Run the scan again with --dkim-selector if you know the selector. |

## Repository Hygiene

| Item | Value |
|---|---|
| Repository Path | `N/A` |
| Files Checked | `25` |
| .gitignore | Yes |
| README.md | Yes |
| Dockerfile | No |
| .dockerignore | No |
| Sensitive Files | `0` |
| Database Files | `0` |
| Secret Hits | `0` |

### Score

| Score | Rating | High | Medium | Low | Info |
|---:|---|---:|---:|---:|---:|
| 100 / 100 | A | 0 | 0 | 0 | 0 |

### Findings

No security findings found.

## Safety Notice

WebTrust Auditor is intended for defensive security review, learning and authorized assessments.

Default website checks are basic readiness checks. Full website checks, when enabled, are intended only for websites you own or are authorized to test.

The tool does not perform directory brute-forcing, crawling, fuzzing, exploitation, authentication bypass, POST requests or destructive actions.
