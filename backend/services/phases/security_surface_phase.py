"""Phase helpers for CORS/takeover/email/swagger/S3/WPScan/CSP security surface checks."""

from collections.abc import Awaitable, Callable
import asyncio
import os

from backend.models import Scope
from backend.services import tool_runner
from backend.services.scope_parser import is_in_scope


EventEmitter = Callable[[str, dict], Awaitable[None]]


async def run_security_surface_phase(
    *,
    scan_dir: str,
    scope: Scope,
    live_urls: list[str],
    all_subdomains: set[str],
    all_target_urls: list[str],
    takeover_timeout_s: int,
    emit: EventEmitter,
    detected_techs: set[str] | None = None,
    http_results: list[dict] | None = None,
    wpscan_api_token: str = "",
) -> dict:
    await emit("phase_start", {"phase": "cors_check"})
    await emit("tool_start", {"tool": "cors_checker", "detail": f"{min(len(live_urls), 120)} live URLs"})
    cors_out = os.path.join(scan_dir, "cors.jsonl")
    cors_findings = await tool_runner.run_cors_checker(live_urls, cors_out)
    await emit("tool_done", {"tool": "cors_checker", "count": len(cors_findings)})
    await emit("phase_done", {"phase": "cors_check", "issues": len(cors_findings)})

    await emit("phase_start", {"phase": "subdomain_takeover"})
    await emit(
        "tool_start",
        {
            "tool": "subdomain_takeover",
            "detail": f"{min(len(list(all_subdomains)), 200)} subdomains",
        },
    )
    takeover_out = os.path.join(scan_dir, "takeovers.jsonl")
    try:
        takeover_findings = await asyncio.wait_for(
            tool_runner.run_subdomain_takeover(list(all_subdomains), takeover_out),
            timeout=takeover_timeout_s,
        )
    except asyncio.TimeoutError:
        takeover_findings = []
        await emit("tool_error", {"tool": "subdomain_takeover", "error": f"timeout after {takeover_timeout_s}s"})
    await emit("tool_done", {"tool": "subdomain_takeover", "count": len(takeover_findings)})
    await emit("phase_done", {"phase": "subdomain_takeover", "vulnerable": len(takeover_findings)})

    await emit("phase_start", {"phase": "email_security"})
    await emit("tool_start", {"tool": "email_security", "detail": f"{len(scope.in_scope_domains)} domains"})
    email_out = os.path.join(scan_dir, "email_security.jsonl")
    email_findings = await tool_runner.run_email_security(scope.in_scope_domains, email_out)
    await emit("tool_done", {"tool": "email_security", "count": len(email_findings)})
    await emit("phase_done", {"phase": "email_security", "issues": len(email_findings)})

    await emit("phase_start", {"phase": "swagger_discovery"})
    await emit("tool_start", {"tool": "swagger_discovery", "detail": f"{len(live_urls)} live hosts"})
    swagger_out = os.path.join(scan_dir, "swagger.jsonl")
    swagger_findings = await tool_runner.run_swagger_discovery(live_urls, swagger_out)
    for swagger_hit in swagger_findings:
        for api_path in swagger_hit.get("sample_paths", []):
            full_url = swagger_hit["base_url"].rstrip("/") + api_path
            if is_in_scope(full_url, scope) and full_url not in all_target_urls:
                all_target_urls.append(full_url)
    await emit("tool_done", {"tool": "swagger_discovery", "count": len(swagger_findings)})
    await emit(
        "phase_done",
        {
            "phase": "swagger_discovery",
            "specs_found": len(swagger_findings),
            "new_endpoints": sum(s.get("endpoints_count", 0) for s in swagger_findings),
        },
    )

    await emit("phase_start", {"phase": "s3_enum"})
    await emit("tool_start", {"tool": "s3_enum", "detail": f"{len(scope.in_scope_domains)} domains → bucket variants"})
    s3_out = os.path.join(scan_dir, "s3_buckets.jsonl")
    s3_findings = await tool_runner.run_s3_enum(scope.in_scope_domains, s3_out)
    await emit("tool_done", {"tool": "s3_enum", "count": len(s3_findings)})
    await emit("phase_done", {"phase": "s3_enum", "public_buckets": len(s3_findings)})

    # ── WPScan (only when WordPress detected) ────────────────────────────────
    wpscan_findings: list[dict] = []
    _techs = detected_techs or set()
    if "wordpress" in _techs or "woocommerce" in _techs:
        wp_targets = [u for u in live_urls if is_in_scope(u, scope)][:3]
        if wp_targets:
            await emit("phase_start", {"phase": "wpscan"})
            for wp_url in wp_targets:
                await emit("tool_start", {"tool": "wpscan", "detail": wp_url})
                wpscan_out = os.path.join(scan_dir, f"wpscan_{len(wpscan_findings)}.json")
                try:
                    results = await tool_runner.run_wpscan(
                        wp_url, wpscan_out, api_token=wpscan_api_token
                    )
                    wpscan_findings.extend(results)
                    await emit("tool_done", {"tool": "wpscan", "count": len(results), "url": wp_url})
                except Exception as e:
                    await emit("tool_error", {"tool": "wpscan", "error": str(e)[:120]})
            await emit("phase_done", {"phase": "wpscan", "findings": len(wpscan_findings)})

    # ── CSP Analyzer ─────────────────────────────────────────────────────────
    csp_findings: list[dict] = []
    if http_results:
        await emit("phase_start", {"phase": "csp_analysis"})
        await emit("tool_start", {"tool": "csp_analyzer", "detail": f"{len(http_results)} HTTP results"})
        csp_out = os.path.join(scan_dir, "csp_findings.jsonl")
        try:
            csp_findings = await tool_runner.run_csp_analyzer(http_results, csp_out)
        except Exception:
            pass
        await emit("tool_done", {"tool": "csp_analyzer", "count": len(csp_findings)})
        await emit("phase_done", {"phase": "csp_analysis", "issues": len(csp_findings)})

    return {
        "all_target_urls": all_target_urls,
        "cors_findings": cors_findings,
        "takeover_findings": takeover_findings,
        "email_findings": email_findings,
        "swagger_findings": swagger_findings,
        "s3_findings": s3_findings,
        "wpscan_findings": wpscan_findings,
        "csp_findings": csp_findings,
    }
