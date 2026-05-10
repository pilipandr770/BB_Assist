"""
Finding filter — three-layer validation before any report is generated.

Layer 1: Scope compliance (fast, local check)
Layer 2: Impact assessment via Claude (AI review)
Layer 3: PoC confirmation (tool-based validation)

A finding must pass ALL THREE to become a report candidate.
Rejected findings are saved to workspace/findings/rejected/ with reason.
"""

from backend.models import Finding, FilterResult, PocResult, Scope
from backend.services import scope_parser, claude_service, poc_validator


async def run_all_layers(
    finding: Finding,
    scope: Scope,
    raw_program_text: str,
) -> tuple[bool, str]:
    """
    Run all three filter layers in sequence.
    Returns (passed: bool, reason: str).
    """
    # Layer 1: fast local scope check
    passed, reason = check_scope_layer(finding, scope)
    if not passed:
        return False, f"[L1-Scope] {reason}"

    # Layer 2: Claude impact assessment
    passed, filter_result = await check_impact_layer(finding, scope, raw_program_text)
    if not passed:
        return False, f"[L2-Impact] {filter_result.reason}"

    # Attach filter result to finding for later use
    finding.filter_result = filter_result
    if filter_result.severity:
        finding.severity = filter_result.severity

    # Layer 3: PoC confirmation
    passed, poc_result = await check_poc_layer(finding)
    finding.poc_result = poc_result

    if not passed:
        # Don't fail completely — move to manual review bucket
        # Caller should check finding.poc_result.confirmed
        return False, f"[L3-PoC] Needs manual review: {poc_result.evidence}"

    return True, "approved"


def check_scope_layer(finding: Finding, scope: Scope) -> tuple[bool, str]:
    """
    Layer 1: Fast local scope check.
    - Is finding.url in scope?
    - Is finding.vuln_type in excluded_vuln_types?
    """
    if not scope_parser.is_in_scope(finding.url, scope):
        return False, f"URL {finding.url} is not in scope"

    if scope_parser.is_excluded_vuln_type(finding.vuln_type, scope):
        return False, f"Vulnerability type '{finding.vuln_type}' is excluded by program rules"

    return True, "in scope"


async def check_impact_layer(
    finding: Finding,
    scope: Scope,
    raw_program_text: str,
) -> tuple[bool, FilterResult]:
    """
    Layer 2: Claude evaluates if finding has real business impact.
    """
    filter_result = await claude_service.filter_finding(finding, scope, raw_program_text)
    return filter_result.approved, filter_result


async def check_poc_layer(finding: Finding) -> tuple[bool, PocResult]:
    """
    Layer 3: Attempt to confirm vulnerability with a PoC.
    Returns (confirmed, PocResult).
    If PoC cannot be automated, returns (False, manual_review_poc) — not a hard rejection.
    """
    poc_result = await poc_validator.attempt_poc(finding)
    return poc_result.confirmed, poc_result
