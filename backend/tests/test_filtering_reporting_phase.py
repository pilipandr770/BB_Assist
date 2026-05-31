import json
import os

from backend.models import Finding, ScanJob, Scope, Severity
from backend.services.phases import filtering_reporting_phase


async def _fake_run_all_layers(finding, _scope, _program_raw_text):
    if "reject" in finding.title.lower():
        return False, "duplicate"
    return True, "valid"


async def _fake_report_generate(_finding, _scope):
    class _Report:
        id = "rep-1"
        title = "Generated"

    return _Report()


async def _fake_capture_evidence(_raw, _json_out, _png_out):
    return {"screenshot": {"saved": True}, "key_validation": {"validated": False}}


async def _fake_save_finding(**_kwargs):
    return None


async def _fake_send_critical_finding(**_kwargs):
    return None


def _to_finding(raw, job):
    return Finding(
        id=raw.get("id", "f-1"),
        scan_id=job.id,
        program_id=job.program_id,
        tool="nuclei",
        title=raw.get("info", {}).get("name", "Test"),
        url=raw.get("matched-at", "https://app.example.com"),
        severity=Severity(raw.get("info", {}).get("severity", "medium")),
        vuln_type=raw.get("type", "unknown"),
        raw_output=json.dumps(raw),
    )


async def test_run_filtering_reporting_phase(monkeypatch, tmp_path):
    monkeypatch.setattr(filtering_reporting_phase.finding_filter, "run_all_layers", _fake_run_all_layers)
    monkeypatch.setattr(filtering_reporting_phase.report_generator, "generate", _fake_report_generate)
    monkeypatch.setattr(filtering_reporting_phase.tool_runner, "capture_finding_evidence", _fake_capture_evidence)
    monkeypatch.setattr(filtering_reporting_phase.database, "save_finding", _fake_save_finding)
    monkeypatch.setattr(filtering_reporting_phase.telegram_notifier, "send_critical_finding", _fake_send_critical_finding)

    events = []

    async def emit(event_type, data):
        events.append((event_type, data))

    finding_dir = str(tmp_path / "findings")
    os.makedirs(os.path.join(finding_dir, "filtered"), exist_ok=True)
    os.makedirs(os.path.join(finding_dir, "rejected"), exist_ok=True)

    job = ScanJob(id="scan-1", program_id="prog-1")
    scope = Scope(in_scope_domains=["*.example.com"], in_scope_urls=["https://app.example.com"])

    raw_findings = [
        {
            "id": "ok-1",
            "info": {"name": "Exposed Secret in JavaScript", "severity": "high", "tags": ["token-disclosure"]},
            "matched-at": "https://app.example.com/app.js",
            "type": "token-disclosure",
            "_source": "js_scanner",
        },
        {
            "id": "rej-1",
            "info": {"name": "Reject this finding", "severity": "low", "tags": ["misc"]},
            "matched-at": "https://app.example.com/reject",
            "type": "misc",
        },
    ]

    result = await filtering_reporting_phase.run_filtering_reporting_phase(
        raw_findings=raw_findings,
        job=job,
        scope=scope,
        program_raw_text="",
        program_name="Program",
        finding_dir=finding_dir,
        scan_dir=str(tmp_path),
        to_finding=_to_finding,
        emit=emit,
    )

    assert result["approved_count"] == 1
    assert result["rejected_count"] == 1
    assert result["reports_count"] == 1
    assert any(evt[0] == "evidence_captured" for evt in events)
    assert any(evt[0] == "report_generated" for evt in events)
