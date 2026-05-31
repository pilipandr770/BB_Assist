from datetime import datetime, timedelta

from backend.models import ScanJob, ScanStatus
from backend.services.phases import scan_finalize_phase


async def _fake_update_scan_status(*_args, **_kwargs):
    return None


async def _fake_send_scan_done(**_kwargs):
    return None


def _fake_usage_delta_since(_snapshot):
    return {"estimated_cost_usd": 1.23, "calls": 5}


async def test_finalize_scan_success(monkeypatch):
    monkeypatch.setattr(scan_finalize_phase.database, "update_scan_status", _fake_update_scan_status)
    monkeypatch.setattr(scan_finalize_phase.telegram_notifier, "send_scan_done", _fake_send_scan_done)
    monkeypatch.setattr(scan_finalize_phase.claude_service, "usage_delta_since", _fake_usage_delta_since)

    events = []

    async def emit(event_type, data):
        events.append((event_type, data))

    saved = {}

    async def save_job(job, program_id):
        saved["job"] = job
        saved["program_id"] = program_id

    job = ScanJob(id="scan-1", program_id="prog-1", status=ScanStatus.running)
    job.started_at = datetime.utcnow() - timedelta(minutes=10)

    result = await scan_finalize_phase.finalize_scan_success(
        job=job,
        program_id="prog-1",
        program_name="Program",
        scan_id="scan-1",
        approved_count=3,
        rejected_count=2,
        llm_usage_start={"estimated_cost_usd": 0.0},
        save_job=save_job,
        emit=emit,
        redis=None,
    )

    assert result["estimated_cost_usd"] == 1.23
    assert job.status == ScanStatus.done
    assert job.findings_count == 3
    assert any(evt[0] == "scan_done" for evt in events)
    assert saved["program_id"] == "prog-1"


async def test_finalize_scan_failure(monkeypatch):
    monkeypatch.setattr(scan_finalize_phase.database, "update_scan_status", _fake_update_scan_status)
    monkeypatch.setattr(scan_finalize_phase.claude_service, "usage_delta_since", _fake_usage_delta_since)

    events = []

    async def emit(event_type, data):
        events.append((event_type, data))

    async def save_job(_job, _program_id):
        return None

    job = ScanJob(id="scan-2", program_id="prog-2", status=ScanStatus.running)

    result = await scan_finalize_phase.finalize_scan_failure(
        job=job,
        program_id="prog-2",
        scan_id="scan-2",
        error=RuntimeError("boom"),
        llm_usage_start={"estimated_cost_usd": 0.0},
        save_job=save_job,
        emit=emit,
        redis=None,
    )

    assert result["estimated_cost_usd"] == 1.23
    assert job.status == ScanStatus.failed
    assert any(evt[0] == "scan_error" for evt in events)
