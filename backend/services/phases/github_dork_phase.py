"""Phase helper for passive GitHub dorking."""

from collections.abc import Awaitable, Callable
import os

from backend.services import tool_runner


EventEmitter = Callable[[str, dict], Awaitable[None]]


async def run_github_dork_phase(
    *,
    scope_domains: list[str],
    scan_dir: str,
    github_token: str | None,
    emit: EventEmitter,
) -> list[dict]:
    await emit("phase_start", {"phase": "github_dork"})
    await emit("tool_start", {"tool": "github_dork", "detail": f"{len(scope_domains)} domains"})

    github_out = os.path.join(scan_dir, "github_dork.jsonl")
    findings = await tool_runner.run_github_dork(scope_domains, github_out, github_token)

    await emit("tool_done", {"tool": "github_dork", "count": len(findings)})
    await emit("phase_done", {"phase": "github_dork", "secrets": len(findings)})
    return findings
