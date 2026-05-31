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
