import os

from backend.models import ScanJob, Scope
from backend.services.phases import persist_raw_findings_phase


class _Program:
    def __init__(self):
        self.name = "Program"
        self.raw_text = ""
        self.scope = Scope(in_scope_domains=["*.example.com"], in_scope_urls=["https://app.example.com"])


async def _fake_run_all_layers(_finding, _scope, _raw_text):
    return True, "ok"


async def _fake_report_generate(_finding, _scope):
    class _Report:
        id = "rep-1"
        title = "Report"

    return _Report()


async def _fake_send_critical_finding(**_kwargs):
    return None


async def _fake_send_scan_done(**_kwargs):
    return None


async def _fake_save_finding(**_kwargs):
    return None


async def _fake_update_scan_status(*_args, **_kwargs):
    return None


def _fake_usage_delta_since(_snapshot):
    return {"estimated_cost_usd": 0.42}


async def test_persist_raw_findings_phase(monkeypatch, tmp_path):
    monkeypatch.setattr(persist_raw_findings_phase.finding_filter, "run_all_layers", _fake_run_all_layers)
    monkeypatch.setattr(persist_raw_findings_phase.report_generator, "generate", _fake_report_generate)
    monkeypatch.setattr(persist_raw_findings_phase.telegram_notifier, "send_critical_finding", _fake_send_critical_finding)
    monkeypatch.setattr(persist_raw_findings_phase.telegram_notifier, "send_scan_done", _fake_send_scan_done)
    monkeypatch.setattr(persist_raw_findings_phase.database, "save_finding", _fake_save_finding)
    monkeypatch.setattr(persist_raw_findings_phase.database, "update_scan_status", _fake_update_scan_status)
    monkeypatch.setattr(persist_raw_findings_phase.claude_service, "usage_delta_since", _fake_usage_delta_since)

    events = []

    async def emit(event_type, data):
        events.append((event_type, data))

    async def load_scope_and_program(_program_id):
        return _Program()

    saved = {}

    async def save_job(job, program_id):
        saved["job"] = job
        saved["program_id"] = program_id

    finding_dir = str(tmp_path / "findings")
    os.makedirs(os.path.join(finding_dir, "filtered"), exist_ok=True)
    os.makedirs(os.path.join(finding_dir, "rejected"), exist_ok=True)

    job = ScanJob(id="scan-1", program_id="prog-1")

    await persist_raw_findings_phase.persist_raw_findings_phase(
        redis=None,
        scan_id="scan-1",
        program_id="prog-1",
        raw_findings=[
            {
                "tool": "nuclei_api",
                "title": "API Finding",
                "url": "https://app.example.com/api",
                "severity": "high",
                "vuln_type": "api",
                "raw_output": "{}",
            }
        ],
        job=job,
        finding_dir=finding_dir,
        llm_usage_start={"estimated_cost_usd": 0.0},
        load_scope_and_program=load_scope_and_program,
        save_job=save_job,
        emit=emit,
    )

    assert saved["program_id"] == "prog-1"
    assert job.findings_count == 1
    assert any(evt[0] == "scan_complete" for evt in events)
