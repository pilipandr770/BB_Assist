"""Phase helper to persist raw findings for non-web pipelines."""

from collections.abc import Awaitable, Callable
from datetime import datetime
import json
import os
import uuid

import aiofiles

from backend import database
from backend.models import Finding, ScanJob, ScanStatus, Severity
from backend.services import claude_service, finding_filter, report_generator, telegram_notifier


EventEmitter = Callable[[str, dict], Awaitable[None]]
LoadProgramFn = Callable[[str], Awaitable[object]]
SaveJobFn = Callable[[ScanJob, str], Awaitable[None]]


async def persist_raw_findings_phase(
    *,
    redis,
    scan_id: str,
    program_id: str,
    raw_findings: list[dict],
    job: ScanJob,
    finding_dir: str,
    llm_usage_start: dict | None,
    load_scope_and_program: LoadProgramFn,
    save_job: SaveJobFn,
    emit: EventEmitter,
) -> None:
    approved_count = 0
    rejected_count = 0

    program = await load_scope_and_program(program_id)
    scope = program.scope

    for raw in raw_findings:
        try:
            try:
                severity = Severity(raw.get("severity", "informative").lower())
            except ValueError:
                severity = Severity.informative

            finding = Finding(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                program_id=program_id,
                tool=raw.get("tool", "unknown"),
                title=raw.get("title", "Untitled"),
                url=raw.get("url", ""),
                severity=severity,
                vuln_type=raw.get("vuln_type", "unknown"),
                raw_output=raw.get("raw_output", ""),
            )

            passed, reason = await finding_filter.run_all_layers(
                finding,
                scope,
                program.raw_text,
            )

            if passed:
                approved_count += 1
                finding_path = os.path.join(finding_dir, "filtered", f"{finding.id}.json")
                async with aiofiles.open(finding_path, "w") as f:
                    await f.write(finding.model_dump_json(indent=2))

                await emit(
                    "finding_approved",
                    {
                        "id": finding.id,
                        "title": finding.title,
                        "severity": finding.severity,
                        "reason": reason,
                    },
                )

                await database.save_finding(
                    finding_id=finding.id,
                    scan_id=scan_id,
                    title=finding.title,
                    severity=finding.severity.value,
                    vuln_type=finding.vuln_type,
                    target=finding.url,
                    passed_filter=1,
                )

                if finding.severity in (Severity.critical, Severity.high):
                    await telegram_notifier.send_critical_finding(
                        program_name=program.name,
                        title=finding.title,
                        severity=finding.severity.value,
                        target=finding.url,
                    )

                try:
                    report = await report_generator.generate(finding, scope)
                    job.reports_count += 1
                    async with aiofiles.open(finding_path, "w") as f:
                        await f.write(finding.model_dump_json(indent=2))
                    await emit(
                        "report_generated",
                        {
                            "finding_id": finding.id,
                            "report_id": report.id,
                            "title": report.title,
                        },
                    )
                except Exception as report_error:
                    await emit(
                        "report_error",
                        {
                            "finding_id": finding.id,
                            "error": str(report_error),
                        },
                    )
            else:
                rejected_count += 1
                rejected_path = os.path.join(finding_dir, "rejected", f"{finding.id}.json")
                async with aiofiles.open(rejected_path, "w") as f:
                    await f.write(
                        json.dumps(
                            {
                                **json.loads(finding.model_dump_json()),
                                "rejection_reason": reason,
                            },
                            indent=2,
                        )
                    )
                await emit(
                    "finding_rejected",
                    {
                        "title": finding.title,
                        "reason": reason,
                    },
                )
        except Exception as finding_error:
            rejected_count += 1
            await emit(
                "finding_error",
                {
                    "error": str(finding_error),
                    "raw_title": str(raw.get("title", ""))[:120],
                },
            )

    job.findings_count += approved_count
    job.status = ScanStatus.done
    job.finished_at = datetime.utcnow()

    llm_usage = None
    if llm_usage_start is not None:
        llm_usage = claude_service.usage_delta_since(llm_usage_start)
        job.llm_cost_usd = float(llm_usage.get("estimated_cost_usd", 0.0) or 0.0)

    await save_job(job, program_id)
    await database.update_scan_status(
        job.id,
        status=job.status.value,
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
        program_name=program.name,
        findings=job.findings_count,
        reports=job.reports_count,
        duration_min=duration_min,
    )

    if llm_usage is not None:
        await emit("llm_usage", llm_usage)

    await emit(
        "scan_complete",
        {
            "approved": approved_count,
            "rejected": rejected_count,
            "reports": job.reports_count,
        },
    )

    if redis:
        await redis.expire(f"scan:{scan_id}:events", 86400)
