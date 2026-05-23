"""
Report generator — produces HackerOne-ready markdown reports.

Output format follows H1 best practices (see docs/REPORT_FORMAT.md).
Claude writes the report based on confirmed finding + PoC evidence.
"""

import json
import os
import re
import uuid
from datetime import datetime

import aiofiles

from backend.config import settings
from backend.models import Finding, Report, Scope, Severity
from backend.services.claude_service import (
    generate_report as claude_generate_report,
    rewrite_report_with_quality_feedback,
)


def _evaluate_report_quality(markdown: str, finding: Finding) -> dict:
    """Rule-based report quality gate with score and actionable issues."""
    issues: list[str] = []
    score = 100
    hard_block_reasons: list[str] = []

    def contains_any(*needles: str) -> bool:
        lower_markdown = markdown.lower()
        return any(needle.lower() in lower_markdown for needle in needles)

    required_sections = [
        "## Summary",
        "## Vulnerability Details",
        "## Steps to Reproduce",
        "## Proof of Concept",
        "## Impact",
        "## Recommended Fix",
    ]
    missing_sections = [sec for sec in required_sections if sec not in markdown]
    if missing_sections:
        issues.append(f"Missing required sections: {', '.join(missing_sections)}")
        score -= min(36, 6 * len(missing_sections))

    placeholder_re = re.compile(
        r"\[[^\]\n]{0,80}(add|step|endpoint|x\.x|severity|cwe|cvss)[^\]\n]{0,80}\]",
        re.IGNORECASE,
    )
    if placeholder_re.search(markdown):
        issues.append("Report still contains placeholder/template markers.")
        score -= 25

    if re.search(r"[\u0400-\u04FF]", markdown):
        issues.append("Report contains Cyrillic characters; output must be English only.")
        score -= 15

    if "CVSS Vector" not in markdown:
        issues.append("CVSS vector is missing.")
        score -= 10

    if "**One-liner (curl):**" not in markdown:
        issues.append("PoC curl one-liner section is missing.")
        score -= 10

    if "**Python script:**" not in markdown:
        issues.append("PoC Python script section is missing.")
        score -= 10

    vuln_type = (finding.vuln_type or "").lower()
    if "cors" in vuln_type:
        if "Authenticated Verification Status" not in markdown:
            issues.append("CORS report must include 'Authenticated Verification Status' section.")
            score -= 20
            hard_block_reasons.append("Missing authenticated verification status for CORS finding.")
        if not contains_any("access-control-allow-origin", "acao"):
            issues.append("CORS report must explicitly show reflected Access-Control-Allow-Origin evidence.")
            score -= 15
            hard_block_reasons.append("Missing ACAO evidence in CORS report.")
        if not contains_any("access-control-allow-credentials", "acac"):
            issues.append("CORS report must explicitly show Access-Control-Allow-Credentials evidence.")
            score -= 15
            hard_block_reasons.append("Missing ACAC evidence in CORS report.")
        if not contains_any("requires authenticated retest", "requires authenticated verification"):
            issues.append("CORS report must distinguish confirmed header behavior from authenticated retest assumptions.")
            score -= 10

    if "idor" in vuln_type:
        if not contains_any("another user's", "another user", "other user's", "other user"):
            issues.append("IDOR report must describe unauthorized access to another user's resource or data.")
            score -= 20
            hard_block_reasons.append("Missing cross-user access statement in IDOR report.")
        if not contains_any("without authorization", "without proper authorization", "without authentication", "access control"):
            issues.append("IDOR report must state the missing authorization check explicitly.")
            score -= 15
            hard_block_reasons.append("Missing authorization failure statement in IDOR report.")
        if not contains_any("id parameter", "object id", "user id", "account id", "record id", "identifier"):
            issues.append("IDOR report should identify the manipulated object identifier or parameter.")
            score -= 10

    if "ssrf" in vuln_type:
        if not contains_any("interactsh", "dns callback", "http callback", "oob", "out-of-band"):
            issues.append("SSRF report must include callback-based proof such as interactsh, DNS, or HTTP callback evidence.")
            score -= 20
            hard_block_reasons.append("Missing callback evidence in SSRF report.")
        if not contains_any("originating from target", "from the target server", "from target ip", "server-side request"):
            issues.append("SSRF report must make clear the callback originated from the target environment.")
            score -= 15
            hard_block_reasons.append("Missing target-origin statement in SSRF report.")
        if not contains_any("internal", "metadata", "169.254.169.254", "aws", "gcp", "azure", "localhost"):
            issues.append("SSRF report should explain the reachable internal or cloud metadata impact path.")
            score -= 10

    # Flag unsupported certainty claims when evidence is not explicit.
    hard_claims = [
        "guaranteed account takeover",
        "attacker can register",
        "attacker registers",
        "attacker registered",
        "attacker owns",
        "attacker-controlled subdomain of",
        "certainly leads to account takeover",
    ]
    lc = markdown.lower()
    suspicious_claims = [c for c in hard_claims if c in lc]
    if suspicious_claims:
        issues.append(
            "Potentially unsupported certainty claims detected: " + ", ".join(suspicious_claims)
        )
        score -= 15
        hard_block_reasons.append("Unsupported certainty claims detected.")

    if hard_block_reasons:
        issues.extend(reason for reason in hard_block_reasons if reason not in issues)

    hard_blocked = bool(hard_block_reasons)
    score = max(0, min(100, score))
    gate_passed = (
        score >= 85
        and not missing_sections
        and not placeholder_re.search(markdown)
        and not hard_blocked
    )
    return {
        "score": score,
        "gate_passed": gate_passed,
        "hard_blocked": hard_blocked,
        "issues": issues,
    }


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
    quality = _evaluate_report_quality(markdown, finding)

    # Up to two deterministic rewrite passes when quality gate fails.
    attempts = 0
    while not quality["gate_passed"] and quality["issues"] and attempts < 2:
        markdown = await rewrite_report_with_quality_feedback(markdown, quality["issues"])
        quality = _evaluate_report_quality(markdown, finding)
        attempts += 1

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
    report_path = await save_report(report, program_slug, quality)
    finding.report_path = report_path

    return report


async def save_report(report: Report, program_slug: str, quality: dict | None = None) -> str:
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
        "quality": quality or {"score": None, "gate_passed": None, "hard_blocked": None, "issues": []},
    }
    meta_path = os.path.join(report_dir, f"{report.id}.json")
    async with aiofiles.open(meta_path, "w", encoding="utf-8") as f:
        await f.write(json.dumps(meta, indent=2))

    return filepath
