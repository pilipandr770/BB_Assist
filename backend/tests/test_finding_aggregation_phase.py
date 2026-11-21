from backend.models import Scope
from backend.services.phases.finding_aggregation_phase import append_phase_findings


def test_append_phase_findings_adds_expected_records():
    scope = Scope(in_scope_domains=["*.example.com"], in_scope_urls=["https://app.example.com"])
    raw = []

    out = append_phase_findings(
        raw_findings=raw,
        scope=scope,
        nmap_csv_cve_hits=[
            {
                "host": "app.example.com",
                "port": 443,
                "cve": "CVE-2024-0001",
                "title": "Test",
                "severity": "high",
                "service": "nginx",
                "version": "1.24.0",
                "pattern": "nginx",
                "reference": "ref",
            }
        ],
        js_secrets=[{"secret_type": "api_key", "severity": "high", "url": "https://app.example.com/app.js", "match": "x", "context": "y"}],
        bypasses=[],
        cors_findings=[],
        takeover_findings=[],
        email_findings=[],
        swagger_findings=[],
        s3_findings=[],
        dalfox_findings=[],
        cred_urls=[{"url": "https://user@example.com:Passw0rd@app.example.com", "username": "user", "host": "app.example.com", "source": "userinfo"}],
        github_findings=[{"secret_type": "token", "severity": "medium", "repo": "org/repo", "file_path": "a.txt", "html_url": "https://github.com/org/repo/a.txt", "snippet": "secret", "query": "example.com", "_is_org_repo": True}],
        is_in_scope=lambda url, _scope: "example.com" in url,
    )

    assert len(out) >= 4
    assert any(item.get("_source") == "nmap_csv" for item in out)
    assert any(item.get("_source") == "js_scanner" for item in out)
    assert any(item.get("_source") == "gau_credentials" for item in out)
    assert any(item.get("_source") == "github_dork" and item.get("info", {}).get("severity") == "high" for item in out)


def test_append_phase_findings_converts_favicon_findings():
    scope = Scope(in_scope_domains=["*.example.com"], in_scope_urls=["https://app.example.com"])

    out = append_phase_findings(
        raw_findings=[],
        scope=scope,
        nmap_csv_cve_hits=[],
        js_secrets=[],
        bypasses=[],
        cors_findings=[],
        takeover_findings=[],
        email_findings=[],
        swagger_findings=[],
        s3_findings=[],
        dalfox_findings=[],
        cred_urls=[],
        github_findings=[],
        is_in_scope=lambda url, _scope: "example.com" in url,
        favicon_findings=[
            {
                "url": "https://app.example.com",
                "name": "MikroTik RouterOS",
                "description": "MikroTik RouterOS WebFig",
                "cpe": "cpe:2.3:o:mikrotik:routeros",
                "category": "exposed-panels",
                "vuln_type": "exposed-panel",
                "severity": "low",
                "favicon_hash": "1924358485",
            }
        ],
    )

    assert len(out) == 1
    finding = out[0]
    assert finding["_source"] == "favicon_fingerprint"
    assert finding["type"] == "exposed-panel"
    assert finding["info"]["severity"] == "low"
    assert "MikroTik RouterOS" in finding["info"]["name"]
    assert finding["matched-at"] == "https://app.example.com"


def test_append_phase_findings_dalfox_uses_data_field_for_poc_url():
    """
    dalfox's real JSON output puts the full PoC URL (with payload already
    URL-encoded in) under "data" — not "url" (that key doesn't exist in
    real dalfox output, confirmed against a live dalfox v2.13.0 run).
    matched-at must come from "data", or every dalfox finding silently
    gets an empty URL.
    """
    scope = Scope(in_scope_domains=["*.example.com"], in_scope_urls=["https://app.example.com"])

    out = append_phase_findings(
        raw_findings=[],
        scope=scope,
        nmap_csv_cve_hits=[],
        js_secrets=[],
        bypasses=[],
        cors_findings=[],
        takeover_findings=[],
        email_findings=[],
        swagger_findings=[],
        s3_findings=[],
        dalfox_findings=[{
            "type": "V",
            "inject_type": "inHTML-URL",
            "method": "GET",
            "data": "https://app.example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "param": "q",
            "payload": "<script>alert(1)</script>",
            "evidence": "reflected in body",
            "severity": "High",
            "message_str": "Triggered XSS Payload",
        }],
        cred_urls=[],
        github_findings=[],
        is_in_scope=lambda url, _scope: "example.com" in url,
    )

    assert len(out) == 1
    finding = out[0]
    assert finding["_source"] == "dalfox"
    assert finding["matched-at"] == "https://app.example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
    assert finding["_poc_url"] == finding["matched-at"]
    assert finding["info"]["severity"] == "high"
    assert "q" in finding["info"]["name"]


def test_append_phase_findings_converts_shodan_vuln_findings():
    scope = Scope(in_scope_domains=["*.example.com"], in_scope_urls=["https://app.example.com"])

    out = append_phase_findings(
        raw_findings=[],
        scope=scope,
        nmap_csv_cve_hits=[],
        js_secrets=[],
        bypasses=[],
        cors_findings=[],
        takeover_findings=[],
        email_findings=[],
        swagger_findings=[],
        s3_findings=[],
        dalfox_findings=[],
        cred_urls=[],
        github_findings=[],
        is_in_scope=lambda url, _scope: "example.com" in url,
        shodan_vuln_findings=[
            {"host": "app.example.com", "ip": "1.2.3.4", "cve": "CVE-2021-23017", "hostnames": ["app.example.com"]},
        ],
    )

    assert len(out) == 1
    finding = out[0]
    assert finding["_source"] == "shodan"
    assert finding["type"] == "cve"
    assert finding["_cve"] == "CVE-2021-23017"
    assert finding["matched-at"] == "https://app.example.com"
    assert "CVE-2021-23017" in finding["info"]["name"]
