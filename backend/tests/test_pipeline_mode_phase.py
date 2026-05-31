from backend.models import ScanJob, Scope
from backend.services.phases.pipeline_mode_phase import resolve_pipeline_mode_config


async def test_resolve_pipeline_mode_source_repo_autofill():
    saved = {}

    async def save_job(job, program_id):
        saved["program_id"] = program_id
        saved["repo_url"] = job.repo_url

    job = ScanJob(id="scan-1", program_id="prog-1", scan_mode="auto", repo_url="")
    scope = Scope(
        program_type="source_code",
        in_scope_domains=["*.example.com"],
        in_scope_urls=["https://github.com/acme/repo"],
        notes="",
    )

    cfg = await resolve_pipeline_mode_config(
        job=job,
        scope=scope,
        program_id="prog-1",
        save_job=save_job,
    )

    assert cfg["scan_mode"] == "source_code"
    assert saved["program_id"] == "prog-1"
    assert saved["repo_url"] == "https://github.com/acme/repo"


async def test_resolve_pipeline_mode_blocks_nuclei_when_manual_only():
    async def save_job(_job, _program_id):
        return None

    job = ScanJob(id="scan-2", program_id="prog-2", scan_mode="auto")
    scope = Scope(
        program_type="web",
        in_scope_domains=["*.example.com"],
        in_scope_urls=["https://app.example.com"],
        notes="Manual testing only. Please refrain from automated scanners.",
    )

    cfg = await resolve_pipeline_mode_config(
        job=job,
        scope=scope,
        program_id="prog-2",
        save_job=save_job,
    )

    assert cfg["scan_mode"] == "web"
    assert cfg["do_nuclei"] is False
    assert len(cfg["blocked_markers"]) >= 1
