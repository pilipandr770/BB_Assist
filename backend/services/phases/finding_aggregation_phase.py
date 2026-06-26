"""Helpers to convert phase outputs into unified raw finding records."""

from backend.models import Scope


def _in_scope_domain_from_query(scope: Scope, query: str) -> str:
    return next(
        (d.lstrip("*.") for d in (scope.in_scope_domains or []) if d.lstrip("*.") in query),
        scope.in_scope_domains[0].lstrip("*.") if scope.in_scope_domains else "",
    )


def append_phase_findings(
    *,
    raw_findings: list[dict],
    scope: Scope,
    nmap_csv_cve_hits: list[dict],
    js_secrets: list[dict],
    bypasses: list[dict],
    cors_findings: list[dict],
    takeover_findings: list[dict],
    email_findings: list[dict],
    swagger_findings: list[dict],
    s3_findings: list[dict],
    dalfox_findings: list[dict],
    cred_urls: list[dict],
    github_findings: list[dict],
    is_in_scope,
    graphql_findings: list[dict] | None = None,
    jwt_findings: list[dict] | None = None,
    wpscan_findings: list[dict] | None = None,
    csp_findings: list[dict] | None = None,
) -> list[dict]:
    for hit in nmap_csv_cve_hits:
        target_url = f"https://{hit['host']}:{hit['port']}"
        raw_findings.append(
            {
                "_source": "nmap_csv",
                "info": {
                    "name": f"Version-based CVE Candidate: {hit['cve']} ({hit['title']})",
                    "severity": hit["severity"],
                    "tags": ["cve", "version-detection", "nmap"],
                    "description": (
                        f"nmap -sV banner matched CSV rule for {hit['cve']} "
                        f"on {hit['host']}:{hit['port']}. "
                        f"service='{hit['service']}' version='{hit['version']}'. "
                        f"pattern='{hit['pattern']}'. reference='{hit['reference']}'"
                    ),
                },
                "matched-at": target_url,
                "type": "cve",
                "_cve": hit["cve"],
                "_service": hit["service"],
                "_version": hit["version"],
                "_reference": hit["reference"],
            }
        )

    for secret in js_secrets:
        raw_findings.append(
            {
                "_source": "js_scanner",
                "info": {
                    "name": f"Exposed Secret in JavaScript: {secret['secret_type']}",
                    "severity": secret["severity"],
                    "tags": ["token-disclosure", "exposure"],
                },
                "matched-at": secret["url"],
                "type": "token-disclosure",
                "extracted-results": [secret["match"]],
                "_context": secret["context"],
                "_secret_type": secret["secret_type"],
            }
        )

    for bypass in bypasses:
        raw_findings.append(
            {
                "_source": "403_bypass",
                "info": {
                    "name": f"403 Bypass via {bypass['bypass_type'].title()} Manipulation",
                    "severity": bypass["severity"],
                    "tags": ["auth-bypass", "access-control"],
                },
                "matched-at": bypass["url"],
                "type": "auth-bypass",
                "_bypass_payload": bypass["payload"],
                "_bypass_status": bypass["status"],
            }
        )

    for cors in cors_findings:
        raw_findings.append(
            {
                "_source": "cors_checker",
                "info": {
                    "name": f"CORS Misconfiguration — {cors['attack_type'].replace('_', ' ').title()}",
                    "severity": cors["severity"],
                    "tags": ["cors", "misconfig"],
                    "description": cors.get("impact", ""),
                },
                "matched-at": cors["url"],
                "type": "cors-misconfig",
                "_origin_sent": cors["origin_sent"],
                "_acao": cors["acao_header"],
                "_acac": cors["acac_header"],
            }
        )

    for takeover in takeover_findings:
        raw_findings.append(
            {
                "_source": "subdomain_takeover",
                "info": {
                    "name": f"Subdomain Takeover — {takeover['subdomain']} → {takeover['provider']}",
                    "severity": takeover["severity"],
                    "tags": ["subdomain-takeover", "misconfig"],
                    "description": takeover.get("impact", ""),
                },
                "matched-at": f"https://{takeover['subdomain']}",
                "type": "subdomain-takeover",
                "_provider": takeover["provider"],
                "_fingerprint": takeover["fingerprint"],
                "_evidence_url": takeover.get("evidence_url", ""),
            }
        )

    for email_issue in email_findings:
        domain = email_issue["domain"]
        checks = email_issue["checks_failed"]
        target_url = f"https://{domain}"
        issues_text = "; ".join(f"{i['check']}: {i['detail']}" for i in email_issue.get("issues", []))
        raw_findings.append(
            {
                "_source": "email_security",
                "info": {
                    "name": f"Email Security Misconfiguration — {checks} ({domain})",
                    "severity": email_issue["severity"],
                    "tags": ["misconfig", "email-security", "spf", "dmarc"],
                    "description": f"Email security issues detected for {domain}: {issues_text}. Impact: {email_issue['impact']}",
                },
                "matched-at": target_url,
                "type": "email-misconfig",
                "_domain": domain,
                "_checks_failed": checks,
                "_issues": email_issue.get("issues", []),
            }
        )

    for swagger_hit in swagger_findings:
        raw_findings.append(
            {
                "_source": "swagger_discovery",
                "info": {
                    "name": f"Exposed API Specification — {swagger_hit['spec_url']}",
                    "severity": swagger_hit["severity"],
                    "tags": ["exposure", "api-docs", "information-disclosure"],
                    "description": swagger_hit["impact"],
                },
                "matched-at": swagger_hit["spec_url"],
                "type": "exposure",
                "_endpoints_count": swagger_hit["endpoints_count"],
                "_sample_paths": swagger_hit.get("sample_paths", []),
            }
        )

    for s3_hit in s3_findings:
        raw_findings.append(
            {
                "_source": "s3_enum",
                "info": {
                    "name": f"Public S3 Bucket — {s3_hit['bucket']}",
                    "severity": s3_hit["severity"],
                    "tags": ["exposure", "s3", "misconfig", "cloud"],
                    "description": s3_hit["impact"],
                },
                "matched-at": s3_hit.get("scope_url") or s3_hit["url"],
                "type": "exposure",
                "_bucket": s3_hit["bucket"],
                "_publicly_listed": s3_hit["publicly_listed"],
                "_bucket_url": s3_hit["url"],
            }
        )

    for xss in dalfox_findings:
        raw_findings.append(
            {
                "_source": "dalfox",
                "info": {
                    "name": f"Cross-Site Scripting (XSS) — {xss.get('param', 'unknown param')}",
                    "severity": "high",
                    "tags": ["xss", "injection"],
                    "description": str(xss.get("evidence", xss)),
                },
                "matched-at": xss.get("url", ""),
                "type": "xss",
                "_param": xss.get("param", ""),
                "_evidence": str(xss.get("evidence", ""))[:500],
            }
        )

    for cred in cred_urls:
        if is_in_scope(cred["url"], scope):
            source_label = (
                "URL userinfo (RFC-3986 user:password@host format)"
                if cred["source"] == "userinfo"
                else "URL path (credentials embedded in path segment)"
            )
            user_info = f"user: {cred['username']}" if cred["username"] else "pattern matched in URL path"
            raw_findings.append(
                {
                    "_source": "gau_credentials",
                    "info": {
                        "name": f"Credentials Exposed in URL — {cred['host']}",
                        "severity": "high",
                        "tags": ["exposure", "credentials", "sensitive-data"],
                        "description": (
                            f"GAU found a URL with plaintext credentials ({user_info}) "
                            f"via {source_label} for {cred['host']}. "
                            f"Credentials in URLs are logged by proxies, browsers, CDNs, "
                            f"and web server access logs, leading to credential exposure. "
                            f"Evidence URL: {cred['url']}"
                        ),
                    },
                    "matched-at": f"https://{cred['host']}",
                    "type": "exposure",
                    "_credential_url": cred["url"],
                    "_username": cred["username"] or "[extracted from path]",
                    "_password": "[REDACTED]",
                }
            )

    for gh in github_findings:
        query = gh.get("query", "")
        is_org_repo = gh.get("_is_org_repo", False)
        target_domain = _in_scope_domain_from_query(scope, query)
        target_url = f"https://{target_domain}" if target_domain else gh["html_url"]

        severity = gh["severity"]
        if is_org_repo and gh["severity"] in ("medium", "low"):
            severity = "high"

        raw_findings.append(
            {
                "_source": "github_dork",
                "info": {
                    "name": f"Exposed {gh['secret_type']} in {'Official' if is_org_repo else 'Third-Party'} GitHub Repository",
                    "severity": severity,
                    "tags": ["token-disclosure", "exposure", "github"] + (["official-repo"] if is_org_repo else ["third-party"]),
                    "description": (
                        f"Secret '{gh['secret_type']}' for {target_domain} found publicly "
                        f"in {'OFFICIAL org repo' if is_org_repo else 'third-party repo'} "
                        f"{gh['repo']} → {gh['file_path']}. "
                        f"{'This is a COMPANY-OWNED repository — much higher impact.' if is_org_repo else ''}"
                        f"Search query: {query}"
                    ),
                },
                "matched-at": target_url,
                "type": "token-disclosure",
                "_repo": gh["repo"],
                "_file_path": gh["file_path"],
                "_evidence_url": gh["html_url"],
                "_snippet": gh["snippet"],
                "_secret_type": gh["secret_type"],
            }
        )

    for gql in (graphql_findings or []):
        raw_findings.append({
            "_source": "graphql_probe",
            "info": {
                "name": gql["issue"],
                "severity": gql["severity"],
                "tags": ["graphql", "misconfig", "exposure"],
                "description": gql.get("description", gql.get("evidence", "")),
            },
            "matched-at": gql["url"],
            "type": "graphql-misconfig",
            "_evidence": gql.get("evidence", "")[:500],
        })

    for jwt in (jwt_findings or []):
        raw_findings.append({
            "_source": "jwt_probe",
            "info": {
                "name": f"JWT Vulnerability — {jwt['issue']}",
                "severity": jwt["severity"],
                "tags": ["jwt", "auth", "cryptography"],
                "description": jwt.get("evidence", ""),
            },
            "matched-at": jwt.get("token_location", "jwt"),
            "type": "jwt-vulnerability",
            "_evidence": jwt.get("evidence", "")[:500],
            "_location": jwt.get("token_location", ""),
        })

    for wp in (wpscan_findings or []):
        vuln_type_map = {
            "vulnerable-plugin":         "outdated-component",
            "vulnerable-theme":          "outdated-component",
            "vulnerable-wordpress-core": "outdated-component",
            "xmlrpc-enabled":            "misconfig",
            "wp-user-enum":              "information-disclosure",
            "wp-readme-exposed":         "information-disclosure",
            "wp-debug-log":              "exposure",
        }
        wp_type = wp.get("type", "unknown")
        cve_list = wp.get("cve", [])
        cve_str = ", ".join(cve_list[:3]) if cve_list else ""
        name = wp.get("title", f"WPScan: {wp_type}")

        tags = ["wordpress", "cms"]
        if cve_str:
            tags.append("cve")
        if "plugin" in wp_type:
            tags.append("plugin")
        elif "theme" in wp_type:
            tags.append("theme")

        desc = wp.get("description", "")
        if not desc:
            parts = []
            if wp.get("plugin"):
                parts.append(f"Plugin: {wp['plugin']} v{wp.get('plugin_version', '?')}")
            if wp.get("theme"):
                parts.append(f"Theme: {wp['theme']} v{wp.get('theme_version', '?')}")
            if wp.get("wp_version"):
                parts.append(f"WordPress core v{wp['wp_version']}")
            if cve_str:
                parts.append(f"CVE(s): {cve_str}")
            if wp.get("fixed_in"):
                parts.append(f"Fixed in: {wp['fixed_in']}")
            if wp.get("users_count"):
                parts.append(f"{wp['users_count']} user(s) enumerated")
            desc = ". ".join(parts) if parts else name

        raw_findings.append({
            "_source": "wpscan",
            "info": {
                "name": name,
                "severity": wp.get("severity", "medium"),
                "tags": tags,
                "description": desc,
            },
            "matched-at": wp.get("url", ""),
            "type": vuln_type_map.get(wp_type, "misconfig"),
            "_wpscan_type": wp_type,
            "_cvss": wp.get("cvss"),
            "_cve": cve_list,
            "_fixed_in": wp.get("fixed_in", ""),
            "_plugin": wp.get("plugin", ""),
            "_theme": wp.get("theme", ""),
        })

    for csp in (csp_findings or []):
        issues_text = "; ".join(
            i.get("description", i.get("issue", ""))
            for i in (csp.get("issues") or [])
        )
        raw_findings.append({
            "_source": "csp_analyzer",
            "info": {
                "name": (
                    "Missing Content-Security-Policy"
                    if csp.get("type") == "csp-missing"
                    else f"Weak Content-Security-Policy — {csp.get('issues_count', 1)} issue(s)"
                ),
                "severity": csp.get("severity", "medium"),
                "tags": ["csp", "misconfig", "xss"],
                "description": csp.get("impact", issues_text or "CSP policy weakness detected"),
            },
            "matched-at": csp.get("url", ""),
            "type": "misconfig",
            "_csp_type": csp.get("type", "csp-weakness"),
            "_csp_issues": csp.get("issues", []),
            "_csp_header": csp.get("csp", ""),
        })

    return raw_findings
