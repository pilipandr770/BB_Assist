"""
Report generator — produces HackerOne-ready markdown reports.

Output format follows H1 best practices (see docs/REPORT_FORMAT.md).
Claude writes the report based on confirmed finding + PoC evidence.
"""

import json
import os
import uuid
from datetime import datetime

import aiofiles

from backend.config import settings
from backend.models import Finding, Report, Scope, Severity
from backend.services.claude_service import generate_report as claude_generate_report


def _extract_title_and_severity(markdown: str) -> tuple[str, Severity]:
    """Parse the title and severity from the Claude-generated report first line."""
    for line in markdown.splitlines():
        line = line.strip()
        if line.startswith("#"):
            title_line = line.lstrip("#").strip()
            # Format: "[SEVERITY] Title" or "SEVERITY: Title"
            severity = Severity.medium  # default
            for sev in ("critical", "high", "medium", "low", "informative"):
                if sev in title_line.lower():
                    severity = Severity(sev)
                    break
            # Strip severity label from title
            clean_title = (
                title_line
                .replace("[CRITICAL]", "").replace("[HIGH]", "")
                .replace("[MEDIUM]", "").replace("[LOW]", "")
                .replace("[INFORMATIVE]", "").replace("[Info]", "")
                .strip()
            )
            return clean_title or title_line, severity

    return "Vulnerability Report", Severity.medium


async def generate(finding: Finding, scope: Scope) -> Report:
    """
    Generate and save a markdown report for a confirmed finding.
    Calls Claude, wraps in Report model, saves to workspace.
    """
    markdown = await claude_generate_report(finding, scope)

    title, severity = _extract_title_and_severity(markdown)

    report = Report(
        id=str(uuid.uuid4()),
        finding_id=finding.id,
        program_id=finding.program_id,
        markdown=markdown,
        title=title,
        severity=severity,
    )

    # Derive program slug from program_id (slug is stored as program_id in our system)
    program_slug = finding.program_id
    report_path = await save_report(report, program_slug)
    finding.report_path = report_path

    return report


async def save_report(report: Report, program_slug: str) -> str:
    """
    Save report markdown + JSON metadata to workspace directory.
    Returns path to saved .md file.
    """
    report_dir = os.path.join(settings.workspace_dir, program_slug, "reports")
    os.makedirs(report_dir, exist_ok=True)
    filename = f"{report.id}.md"
    filepath = os.path.join(report_dir, filename)

    # Save markdown
    async with aiofiles.open(filepath, "w", encoding="utf-8") as f:
        await f.write(report.markdown)

    # Save JSON metadata alongside — used by list_reports for title/severity/finding_id
    meta = {
        "id": report.id,
        "finding_id": report.finding_id,
        "program_id": report.program_id,
        "title": report.title,
        "severity": report.severity if isinstance(report.severity, str) else report.severity.value,
        "created_at": datetime.utcnow().isoformat(),
    }
    meta_path = os.path.join(report_dir, f"{report.id}.json")
    async with aiofiles.open(meta_path, "w", encoding="utf-8") as f:
        await f.write(json.dumps(meta, indent=2))

    return filepath
