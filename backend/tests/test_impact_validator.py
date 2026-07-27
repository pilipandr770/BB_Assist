import json

from backend.models import Finding, Severity
from backend.services.impact_validator import ProbeStatus, synthesize_from_tool_evidence


def _finding(raw: dict, vuln_type: str = "misc") -> Finding:
    return Finding(
        id="f1",
        scan_id="s1",
        program_id="p1",
        tool=raw.get("_source", "unknown"),
        title=raw.get("info", {}).get("name", "Test finding"),
        url=raw.get("matched-at", "https://app.example.com"),
        severity=Severity.high,
        vuln_type=vuln_type,
        raw_output=json.dumps(raw),
    )


def test_synthesize_sqlmap_confirmed():
    finding = _finding({
        "_source": "sqlmap",
        "info": {"description": "Parameter 'id' appears to be TIME-BASED BLIND injectable"},
        "matched-at": "https://app.example.com/item?id=1",
    })
    probe = synthesize_from_tool_evidence(finding)
    assert probe is not None
    assert probe.status == ProbeStatus.CONFIRMED
    assert probe.vuln_type == "sqlmap_sqli"
    assert "sqlmap" in probe.poc_command


def test_synthesize_dalfox_confirmed():
    finding = _finding({
        "_source": "dalfox",
        "matched-at": "https://app.example.com/search?q=x",
        "_param": "q",
        "_evidence": "<script>alert(1)</script> reflected",
    })
    probe = synthesize_from_tool_evidence(finding)
    assert probe is not None
    assert probe.status == ProbeStatus.CONFIRMED
    assert probe.evidence["param"] == "q"


def test_synthesize_cors_checker_confirmed():
    finding = _finding({
        "_source": "cors_checker",
        "matched-at": "https://api.example.com/me",
        "_origin_sent": "https://evil.com",
        "_acao": "https://evil.com",
        "_acac": "true",
    })
    probe = synthesize_from_tool_evidence(finding)
    assert probe is not None
    assert probe.evidence["access_control_allow_credentials"] == "true"
    assert "evil.com" in probe.poc_command


def test_synthesize_subdomain_takeover_confirmed():
    finding = _finding({
        "_source": "subdomain_takeover",
        "matched-at": "https://old.example.com",
        "_provider": "github",
        "_fingerprint": "There isn't a GitHub Pages site here",
    })
    probe = synthesize_from_tool_evidence(finding)
    assert probe is not None
    assert probe.evidence["provider"] == "github"


def test_synthesize_403_bypass_confirmed():
    finding = _finding({
        "_source": "403_bypass",
        "matched-at": "https://app.example.com/admin",
        "_bypass_payload": "-H 'X-Original-URL: /admin'",
        "_bypass_status": 200,
    })
    probe = synthesize_from_tool_evidence(finding)
    assert probe is not None
    assert probe.evidence["resulting_status"] == 200


def test_synthesize_unknown_source_returns_none():
    finding = _finding({"_source": "nuclei", "matched-at": "https://app.example.com"})
    assert synthesize_from_tool_evidence(finding) is None


def test_synthesize_bad_raw_output_returns_none():
    finding = Finding(
        id="f1", scan_id="s1", program_id="p1", tool="x", title="t",
        url="https://app.example.com", severity=Severity.low, vuln_type="misc",
        raw_output="not json",
    )
    assert synthesize_from_tool_evidence(finding) is None
