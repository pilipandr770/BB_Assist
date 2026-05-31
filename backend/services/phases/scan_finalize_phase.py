"""Helpers for scan job finalization (success/failure status, costs, notifications)."""

from collections.abc import Awaitable, Callable
from datetime import datetime

from backend import database
from backend.models import ScanJob, ScanStatus
from backend.services import claude_service, telegram_notifier


EventEmitter = Callable[[str, dict], Awaitable[None]]
SaveJobFn = Callable[[ScanJob, str], Awaitable[None]]


async def finalize_scan_success(
    *,
    job: ScanJob,
    program_id: str,
    program_name: str,
    scan_id: str,
    approved_count: int,
    rejected_count: int,
    llm_usage_start: dict,
    save_job: SaveJobFn,
    emit: EventEmitter,
    redis=None,
) -> dict:
    job.findings_count = approved_count
    job.status = ScanStatus.done
    job.finished_at = datetime.utcnow()

    llm_usage = claude_service.usage_delta_since(llm_usage_start)
    job.llm_cost_usd = float(llm_usage.get("estimated_cost_usd", 0.0) or 0.0)

    await save_job(job, program_id)
    await database.update_scan_status(
        job.id,
        status=ScanStatus.done.value,
        finished_at=job.finished_at.isoformat() if job.finished_at else None,
        findings_count=job.findings_count,
        reports_count=job.reports_count,
        llm_cost_usd=job.llm_cost_usd,
    )

    if job.started_at and job.finished_at:
        duration_min = int((job.finished_at - job.started_at).total_seconds() // 60)
    else:
        duration_min = 0

    await telegram_notifier.send_scan_done(
        program_name=program_name,
        findings=job.findings_count,
        reports=job.reports_count,
        duration_min=duration_min,
    )

    await emit("llm_usage", llm_usage)
    await emit(
        "scan_done",
        {
            "approved": approved_count,
            "rejected": rejected_count,
            "reports": job.reports_count,
        },
    )

    if redis:
        await redis.expire(f"scan:{scan_id}:events", 86400)

    return llm_usage


async def finalize_scan_failure(
    *,
    job: ScanJob,
    program_id: str,
    scan_id: str,
    error: Exception,
    llm_usage_start: dict,
    save_job: SaveJobFn,
    emit: EventEmitter,
    redis=None,
) -> dict:
    job.status = ScanStatus.failed
    job.finished_at = datetime.utcnow()

    llm_usage = claude_service.usage_delta_since(llm_usage_start)
    job.llm_cost_usd = float(llm_usage.get("estimated_cost_usd", 0.0) or 0.0)

    await save_job(job, program_id)
    await database.update_scan_status(
        job.id,
        status=ScanStatus.failed.value,
        finished_at=job.finished_at.isoformat() if job.finished_at else None,
        findings_count=job.findings_count,
        reports_count=job.reports_count,
        llm_cost_usd=job.llm_cost_usd,
    )

    await emit("llm_usage", llm_usage)
    await emit("scan_error", {"error": str(error)})

    if redis:
        await redis.expire(f"scan:{scan_id}:events", 86400)

    return llm_usage
