"""Phase helpers for SQLi validation and finding filtering/reporting pipeline."""

from collections.abc import Awaitable, Callable
import json
import os

import aiofiles

from backend import database
from backend.models import Finding, ScanJob, Scope, Severity
from backend.models import PocResult
from backend.services import finding_filter, report_generator, telegram_notifier, tool_runner
from backend.services.impact_validator import ProbeStatus, run_for_finding
from backend.services.presubmit_gate import get_gate
from backend.services.scope_parser import is_in_scope


EventEmitter = Callable[[str, dict], Awaitable[None]]
FindingConverter = Callable[[dict, ScanJob], Finding]


async def run_filtering_reporting_phase(
    *,
    raw_findings: list[dict],
    job: ScanJob,
    scope: Scope,
    program_raw_text: str,
    program_name: str,
    finding_dir: str,
    scan_dir: str,
    to_finding: FindingConverter,
    emit: EventEmitter,
) -> dict:
    approved_count = 0
    rejected_count = 0

    sqli_candidates: list[str] = []
    for raw in raw_findings:
        tags = str(raw.get("info", {}).get("tags", [])).lower()
        name = raw.get("info", {}).get("name", "").lower()
        if "sqli" in tags or "sql" in name:
            url = raw.get("matched-at", "")
            if url and is_in_scope(url, scope) and url not in sqli_candidates:
                sqli_candidates.append(url)

    if sqli_candidates:
        await emit("phase_start", {"phase": "sqli_validation"})
        sqlmap_confirmed: list[dict] = []

        for sql_url in sqli_candidates[:3]:
            await emit("tool_start", {"tool": "sqlmap", "detail": sql_url[:120]})
            try:
                sql_results = await tool_runner.run_sqlmap(sql_url, scan_dir)
                sqlmap_confirmed.extend(sql_results)
                await emit("tool_done", {"tool": "sqlmap", "count": len(sql_results)})
            except Exception as sqlmap_error:
                await emit(
                    "tool_done",
                    {
                        "tool": "sqlmap",
                        "count": 0,
                        "note": f"sqlmap unavailable: {str(sqlmap_error)[:80]}",
                    },
                )

        for result in sqlmap_confirmed:
            raw_findings.append(
                {
                    "_source": "sqlmap",
                    "info": {
                        "name": "SQL Injection (Time-Based Blind) — Confirmed by sqlmap",
                        "severity": "high",
                        "tags": ["sqli", "injection"],
                        "description": result["evidence"][:500],
                    },
                    "matched-at": result["url"],
                    "type": "sqli",
                }
            )

        await emit(
            "phase_done",
            {
                "phase": "sqli_validation",
                "candidates": len(sqli_candidates),
                "confirmed": len(sqlmap_confirmed),
            },
        )

    for raw in raw_findings:
        try:
            finding = to_finding(raw, job)

            await emit(
                "finding_evaluating",
                {
                    "title": finding.title,
                    "url": finding.url,
                    "vuln_type": finding.vuln_type,
                },
            )

            passed, reason = await finding_filter.run_all_layers(finding, scope, program_raw_text)

            if passed:
                approved_count += 1

                try:
                    raw_data = json.loads(finding.raw_output)
                    source = raw_data.get("_source", "")
                    if source in ("js_scanner",):
                        evidence_out = os.path.join(scan_dir, f"evidence_{finding.id}.json")
                        evidence_png = os.path.join(scan_dir, f"evidence_{finding.id}.png")
                        evidence_data = await tool_runner.capture_finding_evidence(
                            raw_data,
                            evidence_out,
                            evidence_png,
                        )
                        finding.http_evidence = json.dumps(evidence_data)
                        await emit(
                            "evidence_captured",
                            {
                                "finding_id": finding.id,
                                "source": source,
                                "screenshot_saved": (
                                    evidence_data.get("screenshot", {}) or {}
                                ).get("saved", False),
                                "key_validated": (
                                    evidence_data.get("key_validation", {}) or {}
                                ).get("validated", False),
                            },
                        )
                except Exception:
                    pass

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
                    scan_id=job.id,
                    title=finding.title,
                    severity=finding.severity.value,
                    vuln_type=finding.vuln_type,
                    target=finding.url,
                    passed_filter=1,
                )

                if finding.severity in (Severity.critical, Severity.high):
                    await telegram_notifier.send_critical_finding(
                        program_name=program_name,
                        title=finding.title,
                        severity=finding.severity.value,
                        target=finding.url,
                    )

                # Pre-submission duplicate gate
                gate_decision = await get_gate().evaluate(finding)
                if gate_decision.blocked:
                    await emit(
                        "finding_duplicate",
                        {
                            "finding_id": finding.id,
                            "title":      finding.title,
                            "reason":     gate_decision.reason,
                            "cached":     gate_decision.cached,
                        },
                    )
                    continue

                # Non-destructive PoC validation
                try:
                    probe = await run_for_finding(finding)
                    if probe and probe.status == ProbeStatus.CONFIRMED:
                        finding.poc_result = PocResult(
                            confirmed=True,
                            evidence=json.dumps(probe.evidence, ensure_ascii=False),
                            safe_output=probe.summary(),
                            request=probe.poc_command or None,
                            response_snippet=probe.to_report_block() or None,
                        )
                        await emit(
                            "impact_validated",
                            {
                                "finding_id": finding.id,
                                "vuln_type":  probe.vuln_type,
                                "status":     probe.status.value,
                                "note":       probe.note[:200],
                            },
                        )
                except Exception:
                    pass

                try:
                    report = await report_generator.generate(finding, scope)
                    job.reports_count += 1

                    # Attach REVIEW warnings to report if needed
                    for warn in gate_decision.warning_lines():
                        report.notes = (report.notes or "") + f"\n{warn}"

                    async with aiofiles.open(finding_path, "w") as f:
                        await f.write(finding.model_dump_json(indent=2))

                    await emit(
                        "report_generated",
                        {
                            "finding_id":  finding.id,
                            "report_id":   report.id,
                            "title":       report.title,
                            "dup_status":  gate_decision.status.value,
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
                rejected_data = {
                    **json.loads(finding.model_dump_json()),
                    "rejection_reason": reason,
                }
                rejected_path = os.path.join(finding_dir, "rejected", f"{finding.id}.json")
                async with aiofiles.open(rejected_path, "w") as f:
                    await f.write(json.dumps(rejected_data, indent=2))

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
                    "raw_title": str(raw.get("info", {}).get("name", ""))[:120],
                },
            )

    return {
        "approved_count": approved_count,
        "rejected_count": rejected_count,
        "reports_count": job.reports_count,
    }
