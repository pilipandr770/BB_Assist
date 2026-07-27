from backend.models import Finding, Scope, Severity
from backend.services import report_generator


def _finding(**overrides) -> Finding:
    base = dict(
        id="f1", scan_id="s1", program_id="p1", tool="nuclei",
        title="Test finding", url="https://app.example.com",
        severity=Severity.medium, vuln_type="cors-misconfig",
        raw_output="{}",
    )
    base.update(overrides)
    return Finding(**base)


def test_reconcile_cvss_patches_score_and_title_when_mismatched():
    md = (
        "# [MEDIUM] CORS Misconfiguration on api.example.com\n\n"
        "## Vulnerability Details\n"
        "- **CVSS Score**: 6.0 (Medium)\n"
        "- **CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N\n"
    )
    patched = report_generator._reconcile_cvss_in_markdown(md, 9.1, Severity.critical)
    assert "**CVSS Score**: 9.1 (Critical)" in patched
    assert patched.startswith("# [CRITICAL]")
    assert "6.0 (Medium)" not in patched


def test_evaluate_report_quality_flags_malformed_cvss_vector():
    finding = _finding()
    md_missing = "## Summary\nno cvss section at all\n"
    md_malformed = "## Summary\n**CVSS Vector**: [CVSS:3.1/AV:.../...]\n"
    md_valid = "## Summary\n**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N\n"

    q_missing = report_generator._evaluate_report_quality(md_missing, finding)
    q_malformed = report_generator._evaluate_report_quality(md_malformed, finding)
    q_valid = report_generator._evaluate_report_quality(md_valid, finding)

    assert any("CVSS vector is missing" in i for i in q_missing["issues"])
    assert any("malformed" in i.lower() for i in q_malformed["issues"])
    assert not any("cvss" in i.lower() for i in q_valid["issues"])


async def test_generate_populates_cvss_fields_from_vector(monkeypatch, tmp_path):
    markdown = (
        "# [MEDIUM] SQL Injection on api.example.com\n\n"
        "## Summary\nConfirmed SQLi.\n\n"
        "## Vulnerability Details\n"
        "- **CVSS Score**: 6.0 (Medium)\n"
        "- **CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n\n"
        "## Steps to Reproduce\n1. do the thing\n\n"
        "## Proof of Concept\n"
        "**One-liner (curl):**\n```bash\ncurl https://app.example.com\n```\n"
        "**Python script:**\n```python\nprint('poc')\n```\n\n"
        "## Impact\nBad.\n\n"
        "## Recommended Fix\nUse parameterized queries.\n"
    )

    async def _fake_claude_generate_report(_finding, _scope):
        return markdown

    monkeypatch.setattr(report_generator, "claude_generate_report", _fake_claude_generate_report)
    monkeypatch.setattr(report_generator.settings, "workspace_dir", str(tmp_path))

    finding = _finding(vuln_type="sqli")
    scope = Scope(in_scope_domains=["*.example.com"], in_scope_urls=["https://app.example.com"])

    report = await report_generator.generate(finding, scope)

    assert report.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert report.cvss_score == 9.8
    assert report.severity == Severity.critical
    assert "**CVSS Score**: 9.8 (Critical)" in report.markdown
    assert report.markdown.startswith("# [CRITICAL]")
