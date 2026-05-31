from backend.models import ScanJob, Scope
from backend.services.phases import non_web_pipeline_phase


async def _fake_run_api_scan(**_kwargs):
    return {
        "endpoints": ["/health"],
        "ffuf_findings": [{"status": 200, "url": "https://api.example.com/admin"}],
        "nuclei_findings": [
            {
                "info": {"name": "Exposed API", "severity": "medium", "tags": ["api", "exposure"]},
                "matched-at": "https://api.example.com/openapi.json",
                "template-id": "api-test",
            }
        ],
        "arjun_params": ["id"],
    }


async def test_non_web_api_pipeline_persists_findings(monkeypatch):
    monkeypatch.setattr(non_web_pipeline_phase.tool_runner, "run_api_scan", _fake_run_api_scan)

    events = []
    persisted = {}

    async def emit(event_type, data):
        events.append((event_type, data))

    async def persist_raw_findings(**kwargs):
        persisted.update(kwargs)

    job = ScanJob(id="scan-1", program_id="prog-1", scan_mode="api", api_spec_url="https://api.example.com/openapi.json")
    scope = Scope(in_scope_domains=["*.example.com"], in_scope_urls=["https://api.example.com"])

    handled = await non_web_pipeline_phase.run_non_web_pipeline_phase(
        scan_mode="api",
        job=job,
        scope=scope,
        scan_id=job.id,
        program_id=job.program_id,
        redis=None,
        scan_dir="/tmp/scan",
        finding_dir="/tmp/findings",
        llm_usage_start={"estimated_cost_usd": 0.0},
        emit=emit,
        persist_raw_findings=persist_raw_findings,
    )

    assert handled is True
    assert "raw_findings" in persisted
    assert len(persisted["raw_findings"]) == 2
    assert any(evt[0] == "phase_done" and evt[1].get("phase") == "api_scan" for evt in events)


async def test_non_web_api_without_spec_falls_back_to_web():
    events = []

    async def emit(event_type, data):
        events.append((event_type, data))

    async def persist_raw_findings(**_kwargs):
        raise AssertionError("persist should not be called when api spec is missing")

    job = ScanJob(id="scan-2", program_id="prog-2", scan_mode="api", api_spec_url="")
    scope = Scope(in_scope_domains=["*.example.com"], in_scope_urls=["https://app.example.com"])

    handled = await non_web_pipeline_phase.run_non_web_pipeline_phase(
        scan_mode="api",
        job=job,
        scope=scope,
        scan_id=job.id,
        program_id=job.program_id,
        redis=None,
        scan_dir="/tmp/scan",
        finding_dir="/tmp/findings",
        llm_usage_start=None,
        emit=emit,
        persist_raw_findings=persist_raw_findings,
    )

    assert handled is False
    assert events == []
