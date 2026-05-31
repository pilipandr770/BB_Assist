"""Orchestrator for the full web scan pipeline: passive recon → active recon → nuclei → filter/report."""

from collections.abc import Awaitable, Callable
import asyncio
import json
import os
import uuid
from urllib.parse import urlparse

import aiofiles

from backend.models import Finding, ScanJob, Scope, Severity
from backend.services import tool_runner
from backend.services.phases.active_recon_phase import run_active_recon_core
from backend.services.phases.appsec_probe_phase import run_appsec_probe_phase
from backend.services.phases.content_and_js_phase import run_content_and_js_phase
from backend.services.phases.delta_history_phase import emit_delta_new_surface
from backend.services.phases.finding_aggregation_phase import append_phase_findings
from backend.services.phases.filtering_reporting_phase import run_filtering_reporting_phase
from backend.services.phases.github_dork_phase import run_github_dork_phase
from backend.services.phases.passive_recon_phase import run_passive_recon_phase
from backend.services.phases.security_surface_phase import run_security_surface_phase
from backend.services.phases.url_recon_phase import run_url_recon_phase
from backend.services.scope_parser import is_in_scope


EventEmitter = Callable[[str, dict], Awaitable[None]]


# ── URL target selectors ──────────────────────────────────────────────────────

_SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".mov", ".pdf", ".zip", ".gz",
    ".map", ".min.js",
}

_INTERESTING_PATTERNS = [
    "/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/admin", "/auth",
    "/login", "/register", "/signup", "/user", "/account", "/profile",
    "/upload", "/file", "/download", "/export", "/import",
    "/search", "/query", "/fetch", "/redirect", "/callback", "/oauth",
    "/token", "/reset", "/password", "/verify", "/confirm",
    ".json", ".xml", ".php", ".asp", ".aspx",
]

_INTERESTING_SUB = (
    "api", "admin", "portal", "dashboard", "dev", "staging", "internal",
    "test", "beta", "app", "manage", "console", "panel", "monitor",
    "login", "auth", "upload", "backend", "service", "services",
)

_CDN_SKIP = (
    "edge", "cdn", "rtm", "streaming", "delivery", "media", "img",
    "static", "live", "video", "cam", "thumb", "photo", "image",
    "archive", "mirror", "relay",
)


def select_nuclei_targets(
    all_urls: list[str],
    live_urls: list[str],
    max_urls: int = 500,
) -> list[str]:
    """Pick the best URLs for nuclei. Cap at max_urls to keep scan time < 30 min."""

    def _score(url: str, is_live: bool) -> int:
        score = 0
        try:
            parsed = urlparse(url)
        except Exception:
            return -1
        path = parsed.path.lower()
        if any(path.endswith(ext) for ext in _SKIP_EXT):
            return -1
        if is_live:
            score += 100
        if parsed.query:
            score += 50
            score += min(parsed.query.count("=") * 10, 40)
        for pattern in _INTERESTING_PATTERNS:
            if pattern in path:
                score += 20
                break
        score -= len(path.split("/")) * 2
        return score

    live_set = set(live_urls)
    seen_paths: dict[str, tuple[int, str]] = {}
    for url in all_urls:
        try:
            parsed = urlparse(url)
        except Exception:
            continue
        path_key = (parsed.netloc, parsed.path)
        s = _score(url, url in live_set)
        if s < 0:
            continue
        if path_key not in seen_paths or s > seen_paths[path_key][0]:
            seen_paths[path_key] = (s, url)

    scored = sorted(seen_paths.values(), key=lambda x: x[0], reverse=True)
    return [url for _, url in scored[:max_urls]]


def select_ffuf_targets(live_urls: list[str], max_hosts: int = 5) -> list[str]:
    """Pick the best base hosts for directory fuzzing."""

    def _host_score(url: str) -> int:
        try:
            p = urlparse(url)
        except Exception:
            return -999
        host = p.hostname or ""
        subdomain = host.split(".")[0].lower() if "." in host else host.lower()
        if any(c in host.lower() for c in _CDN_SKIP):
            return -999
        score = 0
        if p.scheme == "https":
            score += 20
        if not p.port:
            score += 15
        elif p.port in (80, 443):
            score += 10
        else:
            score -= 20
        if any(kw == subdomain or subdomain.startswith(kw) for kw in _INTERESTING_SUB):
            score += 40
        return score

    seen_hosts: dict[str, tuple[int, str]] = {}
    for url in live_urls:
        try:
            p = urlparse(url)
            base = f"{p.scheme}://{p.netloc}"
        except Exception:
            continue
        s = _host_score(url)
        if s <= -999:
            continue
        if base not in seen_hosts or s > seen_hosts[base][0]:
            seen_hosts[base] = (s, base)

    scored = sorted(seen_hosts.values(), key=lambda x: x[0], reverse=True)
    return [url for _, url in scored[:max_hosts]]


def nuclei_to_finding(raw: dict, job: ScanJob) -> Finding:
    """Convert a nuclei JSONL output line to a Finding model."""
    info = raw.get("info", {})
    severity_str = info.get("severity", "informative").lower()
    try:
        severity = Severity(severity_str)
    except ValueError:
        severity = Severity.informative
    return Finding(
        id=str(uuid.uuid4()),
        scan_id=job.id,
        program_id=job.program_id,
        tool="nuclei",
        title=info.get("name", raw.get("template-id", "Unknown Finding")),
        url=raw.get("matched-at", raw.get("host", "")),
        severity=severity,
        vuln_type=raw.get("type", info.get("tags", ["unknown"])[0] if info.get("tags") else "unknown"),
        raw_output=json.dumps(raw),
    )


# ── Web pipeline orchestrator ─────────────────────────────────────────────────

async def run_web_pipeline(
    *,
    job: ScanJob,
    program,          # Program model — provides .name, .raw_text, .scope
    scope: Scope,
    scan_id: str,
    program_id: str,
    scan_dir: str,
    finding_dir: str,
    workspace_dir: str,
    do_katana: bool,
    do_ffuf: bool,
    do_arjun: bool,
    arjun_max: int,
    do_nuclei: bool,
    blocked_markers: list,
    prev_subdomains: set[str],
    prev_live_urls: set[str],
    github_token: str,
    takeover_timeout_s: int,
    emit: EventEmitter,
) -> dict:
    """
    Full web scan pipeline: Phase 1 (passive recon) through Phase 4 (filter & report).

    Returns:
        approved_count, rejected_count, all_subdomains, live_urls
    """
    await emit("pipeline_config", {
        "program_type": (scope.program_type or "web").lower(),
        "do_katana": do_katana,
        "do_ffuf": do_ffuf,
        "do_arjun": do_arjun,
        "do_nuclei": do_nuclei,
        "automation_policy_markers": blocked_markers,
    })

    # ── Phase 1: Passive recon ────────────────────────────────────────────────
    await emit("phase_start", {"phase": "passive_recon"})

    all_subdomains: set[str] = set()

    phase1 = await run_passive_recon_phase(scope.in_scope_domains, max_domains=5)

    await emit("pipeline_config", {
        "passive_domains": phase1["passive_domains"],
        "total_scope_domains": len(scope.in_scope_domains),
    })

    all_subdomains.update(phase1["subdomains"])

    recon_dir = os.path.join(workspace_dir, program_id, "recon")
    os.makedirs(recon_dir, exist_ok=True)
    async with aiofiles.open(os.path.join(recon_dir, "passive_subdomains.txt"), "w") as fh:
        await fh.write("\n".join(sorted(all_subdomains)))

    await emit("phase_done", {
        "phase": "passive_recon",
        "subdomains": len(all_subdomains),
        "urls": len(phase1["urls"]),
    })

    # ── Phase 2: Active recon ─────────────────────────────────────────────────
    await emit("phase_start", {"phase": "active_recon"})

    prog_type = (scope.program_type or "web").lower()

    phase2 = await run_active_recon_core(
        scope=scope,
        recon_dir=recon_dir,
        seed_subdomains=all_subdomains,
        emit=emit,
    )
    all_subdomains = phase2["all_subdomains"]
    live_hosts = phase2["live_hosts"]
    nmap_endpoints = phase2["nmap_endpoints"]
    nmap_service_versions = phase2["nmap_service_versions"]
    nmap_csv_cve_hits = phase2["nmap_csv_cve_hits"]

    phase2_urls = await run_url_recon_phase(
        scope=scope,
        recon_dir=recon_dir,
        live_hosts=live_hosts,
        nmap_endpoints=nmap_endpoints,
        nmap_service_versions=nmap_service_versions,
        nmap_csv_cve_hits=nmap_csv_cve_hits,
        do_katana=do_katana,
        program_type=prog_type,
        session_cookies=job.session_cookies,
        auth_header=job.auth_header,
        emit=emit,
    )

    live_urls: list[str] = phase2_urls["live_urls"]
    detected_techs: set[str] = set(phase2_urls["detected_techs"])
    nmap_service_versions = phase2_urls["nmap_service_versions"]
    nmap_csv_cve_hits = phase2_urls["nmap_csv_cve_hits"]
    gau_urls = phase2_urls["gau_urls"]
    crawled_urls = phase2_urls["crawled_urls"]
    all_target_urls: list[str] = phase2_urls["all_target_urls"]
    cred_urls = phase2_urls["cred_urls"]

    await emit("phase_done", {
        "phase": "active_recon",
        "live_hosts": len(live_hosts),
        "target_urls": len(all_target_urls),
        **({"cred_urls": len(cred_urls)} if cred_urls else {}),
    })

    # Delta: emit new surface relative to previous scan
    await emit_delta_new_surface(
        prev_subdomains=prev_subdomains,
        prev_live_urls=prev_live_urls,
        all_subdomains=all_subdomains,
        live_urls=live_urls,
        emit=emit,
    )

    # GitHub dorking
    github_findings = await run_github_dork_phase(
        scope_domains=scope.in_scope_domains,
        scan_dir=scan_dir,
        github_token=github_token,
        emit=emit,
    )

    # Content discovery + JS scanning
    phase_content = await run_content_and_js_phase(
        scan_dir=scan_dir,
        scope=scope,
        live_urls=live_urls,
        all_target_urls=all_target_urls,
        gau_urls=gau_urls,
        crawled_urls=crawled_urls,
        do_ffuf=do_ffuf,
        program_type=prog_type,
        ffuf_target_selector=select_ffuf_targets,
        session_cookies=job.session_cookies,
        auth_header=job.auth_header,
        emit=emit,
    )
    all_target_urls = phase_content["all_target_urls"]
    ffuf_403_urls = phase_content["ffuf_403_urls"]
    js_secrets = phase_content["js_secrets"]

    # AppSec probe (403 bypass, arjun, dalfox)
    phase_appsec = await run_appsec_probe_phase(
        scan_dir=scan_dir,
        scope=scope,
        all_target_urls=all_target_urls,
        ffuf_403_urls=ffuf_403_urls,
        do_arjun=do_arjun,
        arjun_max=arjun_max,
        program_type=prog_type,
        session_cookies=job.session_cookies,
        auth_header=job.auth_header,
        emit=emit,
    )
    all_target_urls = phase_appsec["all_target_urls"]
    bypasses = phase_appsec["bypasses"]
    dalfox_findings = phase_appsec["dalfox_findings"]

    # Security surface (CORS, takeover, email, swagger, S3)
    phase_surface = await run_security_surface_phase(
        scan_dir=scan_dir,
        scope=scope,
        live_urls=live_urls,
        all_subdomains=all_subdomains,
        all_target_urls=all_target_urls,
        takeover_timeout_s=takeover_timeout_s,
        emit=emit,
    )
    all_target_urls = phase_surface["all_target_urls"]
    cors_findings = phase_surface["cors_findings"]
    takeover_findings = phase_surface["takeover_findings"]
    email_findings = phase_surface["email_findings"]
    swagger_findings = phase_surface["swagger_findings"]
    s3_findings = phase_surface["s3_findings"]

    # ── Phase 3: Nuclei ───────────────────────────────────────────────────────
    raw_findings: list[dict] = []
    await emit("phase_start", {"phase": "nuclei_scan"})

    if do_nuclei:
        nuclei_urls = select_nuclei_targets(all_target_urls, live_urls, max_urls=500)
        await emit("tool_start", {
            "tool": "nuclei",
            "detail": f"{len(nuclei_urls)} targets (of {len(all_target_urls)} total)",
        })

        nuclei_out = os.path.join(scan_dir, "nuclei.jsonl")

        async def _ticker() -> None:
            elapsed = 0
            while True:
                await asyncio.sleep(30)
                elapsed += 30
                await emit("nuclei_progress", {"elapsed_s": elapsed, "targets": len(nuclei_urls)})

        ticker_task = asyncio.create_task(_ticker())
        try:
            raw_findings = await tool_runner.run_nuclei(
                nuclei_urls,
                nuclei_out,
                scope,
                detected_techs=detected_techs,
                session_cookies=job.session_cookies,
                auth_header=job.auth_header,
            )
        finally:
            ticker_task.cancel()

        await emit("phase_done", {"phase": "nuclei_scan", "raw_findings": len(raw_findings)})
    else:
        await emit("phase_done", {
            "phase": "nuclei_scan",
            "skipped": True,
            "reason": "program prohibits automated scanners",
        })

    # ── Phase 4: Filter & report ──────────────────────────────────────────────
    await emit("phase_start", {"phase": "filtering"})

    raw_findings = append_phase_findings(
        raw_findings=raw_findings,
        scope=scope,
        nmap_csv_cve_hits=nmap_csv_cve_hits,
        js_secrets=js_secrets,
        bypasses=bypasses,
        cors_findings=cors_findings,
        takeover_findings=takeover_findings,
        email_findings=email_findings,
        swagger_findings=swagger_findings,
        s3_findings=s3_findings,
        dalfox_findings=dalfox_findings,
        cred_urls=cred_urls,
        github_findings=github_findings,
        is_in_scope=is_in_scope,
    )

    phase_filter = await run_filtering_reporting_phase(
        raw_findings=raw_findings,
        job=job,
        scope=scope,
        program_raw_text=program.raw_text,
        program_name=program.name,
        finding_dir=finding_dir,
        scan_dir=scan_dir,
        to_finding=nuclei_to_finding,
        emit=emit,
    )

    return {
        "approved_count": phase_filter["approved_count"],
        "rejected_count": phase_filter["rejected_count"],
        "all_subdomains": all_subdomains,
        "live_urls": live_urls,
    }
