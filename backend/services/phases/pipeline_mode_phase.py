"""Helpers for scan mode resolution and pipeline feature toggles."""

from collections.abc import Awaitable, Callable

from backend.models import ScanJob, Scope
from backend.services.policy_rules import detect_no_automation_policy


SaveJobFn = Callable[[ScanJob, str], Awaitable[None]]


async def resolve_pipeline_mode_config(
    *,
    job: ScanJob,
    scope: Scope,
    program_id: str,
    save_job: SaveJobFn,
) -> dict:
    notes_lower = (scope.notes or "").lower()
    prog_type = (scope.program_type or "web").lower()

    do_katana = prog_type in ("web", "api")
    do_ffuf = prog_type == "web"
    do_arjun = prog_type in ("web", "api")
    arjun_max = 10 if prog_type == "api" else 5

    blocked_automation, blocked_markers = detect_no_automation_policy(notes_lower)
    do_nuclei = not blocked_automation

    scan_mode = (job.scan_mode or "auto").lower()
    if scan_mode == "auto":
        if prog_type == "ip":
            scan_mode = "ip"
        elif prog_type == "source_code" or job.repo_url:
            if not job.repo_url:
                git_urls = [
                    url
                    for url in (scope.in_scope_urls or [])
                    if "github.com" in url or "gitlab.com" in url or "bitbucket.org" in url
                ]
                if git_urls:
                    job.repo_url = git_urls[0]
                    await save_job(job, program_id)
            scan_mode = "source_code" if job.repo_url else "web"
        elif prog_type == "api" or job.api_spec_url:
            scan_mode = "api"
        else:
            scan_mode = "web"

    return {
        "scan_mode": scan_mode,
        "prog_type": prog_type,
        "do_katana": do_katana,
        "do_ffuf": do_ffuf,
        "do_arjun": do_arjun,
        "arjun_max": arjun_max,
        "do_nuclei": do_nuclei,
        "blocked_markers": blocked_markers,
    }
