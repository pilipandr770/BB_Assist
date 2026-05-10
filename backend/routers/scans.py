import asyncio
import json
import os
import uuid
from datetime import datetime

import aiofiles
import redis.asyncio as aioredis
from fastapi import APIRouter, HTTPException
from sse_starlette.sse import EventSourceResponse

from backend.config import settings
from backend.models import ApiResponse, Finding, ScanCreate, ScanJob, ScanStatus, Severity
# settings is used for: workspace_dir, github_token, redis_url
from backend.services import finding_filter, passive_recon, report_generator, tool_runner
from backend.services.scope_parser import is_in_scope

router = APIRouter()

WORKSPACE = settings.workspace_dir


# ── helpers ──────────────────────────────────────────────────────────────────

def _scan_dir(program_id: str, scan_id: str) -> str:
    return os.path.join(WORKSPACE, program_id, "scans", scan_id)


def _finding_dir(program_id: str) -> str:
    return os.path.join(WORKSPACE, program_id, "findings")


def _scan_file(program_id: str, scan_id: str) -> str:
    return os.path.join(_scan_dir(program_id, scan_id), "job.json")


async def _load_scope_and_program(program_id: str):
    """Load program.json and return (program_dict, Scope)."""
    from backend.models import Program
    prog_file = os.path.join(WORKSPACE, program_id, "program.json")
    if not os.path.exists(prog_file):
        raise HTTPException(status_code=404, detail=f"Program '{program_id}' not found")
    async with aiofiles.open(prog_file, encoding="utf-8") as f:
        prog_data = json.loads(await f.read())
    program = Program(**prog_data)
    if not program.scope:
        raise HTTPException(status_code=400, detail="Program has no scope. Generate scope first.")
    return program


async def _save_job(job: ScanJob, program_id: str) -> None:
    path = _scan_file(program_id, job.id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    async with aiofiles.open(path, "w", encoding="utf-8") as f:
        await f.write(job.model_dump_json(indent=2))


async def _load_job(program_id: str, scan_id: str) -> ScanJob:
    path = _scan_file(program_id, scan_id)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    async with aiofiles.open(path, encoding="utf-8") as f:
        return ScanJob(**json.loads(await f.read()))


async def _push_event(redis_client, scan_id: str, event_type: str, data: dict) -> None:
    """Push a structured event to the Redis list for SSE streaming."""
    if redis_client:
        event = json.dumps({"type": event_type, "data": data, "ts": datetime.utcnow().isoformat()})
        await redis_client.rpush(f"scan:{scan_id}:events", event)


async def _get_redis():
    try:
        r = aioredis.from_url(settings.redis_url, decode_responses=True)
        await r.ping()
        return r
    except Exception:
        return None


# ── scan orchestration ────────────────────────────────────────────────────────

def _select_nuclei_targets(all_urls: list[str], live_urls: list[str], max_urls: int = 500) -> list[str]:
    """
    Pick the best URLs for nuclei scanning. Priority:
    1. Live httpx URLs (confirmed reachable, highest value)
    2. URLs with query parameters (most likely to be vulnerable)
    3. URLs that look like API endpoints or interesting paths
    4. Deduplicate by path to avoid redundant scans
    5. Cap at max_urls to keep scan time reasonable (< 30 min)
    """
    from urllib.parse import urlparse, urlunparse

    # Static extensions to skip — nuclei can't find vulns in static files
    SKIP_EXT = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
        ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".mp4", ".mp3", ".avi", ".mov", ".pdf", ".zip", ".gz",
        ".map", ".min.js",  # sourcemaps and minified JS (not injectable)
    }

    # Paths that look like interesting attack surface
    INTERESTING_PATTERNS = [
        "/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/admin", "/auth",
        "/login", "/register", "/signup", "/user", "/account", "/profile",
        "/upload", "/file", "/download", "/export", "/import",
        "/search", "/query", "/fetch", "/redirect", "/callback", "/oauth",
        "/token", "/reset", "/password", "/verify", "/confirm",
        ".json", ".xml", ".php", ".asp", ".aspx",
    ]

    def _score(url: str, is_live: bool) -> int:
        score = 0
        try:
            parsed = urlparse(url)
        except Exception:
            return -1

        path = parsed.path.lower()
        # Skip static files
        if any(path.endswith(ext) for ext in SKIP_EXT):
            return -1

        # Big boost for live httpx-confirmed URLs
        if is_live:
            score += 100

        # Boost for URLs with query params (injectable)
        if parsed.query:
            score += 50
            score += min(parsed.query.count("=") * 10, 40)  # more params = more interesting

        # Boost for interesting path patterns
        for pattern in INTERESTING_PATTERNS:
            if pattern in path:
                score += 20
                break

        # Boost for shorter paths (closer to root = more likely to be meaningful)
        score -= len(path.split("/")) * 2

        return score

    live_set = set(live_urls)

    # Score and deduplicate by (netloc, path) — keep the highest-scored URL per path
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


async def _run_scan(job: ScanJob, approved_plan: str) -> None:
    """
    Full scan pipeline executed as a background task.
    Phase 1: Passive recon
    Phase 2: Active recon (subfinder → dnsx → httpx → gau → katana)
    Phase 3: Nuclei scan
    Phase 4: Filter & validate findings
    Phase 5: Generate reports for approved findings
    """
    program_id = job.program_id
    scan_id = job.id
    scan_dir = _scan_dir(program_id, scan_id)
    finding_dir = _finding_dir(program_id)

    os.makedirs(scan_dir, exist_ok=True)
    os.makedirs(os.path.join(finding_dir, "filtered"), exist_ok=True)
    os.makedirs(os.path.join(finding_dir, "rejected"), exist_ok=True)

    redis = await _get_redis()

    try:
        # Update job status
        job.status = ScanStatus.running
        job.started_at = datetime.utcnow()
        await _save_job(job, program_id)

        program = await _load_scope_and_program(program_id)
        scope = program.scope

        await _push_event(redis, scan_id, "phase_start", {"phase": "passive_recon"})

        # ── Phase 1: Passive recon ────────────────────────────────────────────
        all_subdomains: set[str] = set()
        all_urls: set[str] = set()

        for domain in scope.in_scope_domains:
            base_domain = domain.lstrip("*.")
            passive = await passive_recon.run_all_passive(base_domain)
            all_subdomains.update(passive.get("subdomains", []))
            all_urls.update(passive.get("urls", []))

        # Save passive recon results
        recon_dir = os.path.join(WORKSPACE, program_id, "recon")
        os.makedirs(recon_dir, exist_ok=True)
        async with aiofiles.open(os.path.join(recon_dir, "passive_subdomains.txt"), "w") as f:
            await f.write("\n".join(sorted(all_subdomains)))

        await _push_event(redis, scan_id, "phase_done", {
            "phase": "passive_recon",
            "subdomains": len(all_subdomains),
            "urls": len(all_urls),
        })

        # ── Phase 2: Active recon ─────────────────────────────────────────────
        await _push_event(redis, scan_id, "phase_start", {"phase": "active_recon"})

        # subfinder
        await _push_event(redis, scan_id, "tool_start", {"tool": "subfinder", "detail": f"{len(scope.in_scope_domains)} domains"})
        subfinder_out = os.path.join(recon_dir, "subfinder.txt")
        active_subs = await tool_runner.run_subfinder(scope.in_scope_domains, subfinder_out)
        all_subdomains.update(active_subs)
        await _push_event(redis, scan_id, "tool_done", {"tool": "subfinder", "count": len(active_subs)})

        # Scope-filter subdomains
        scoped_subs = [s for s in all_subdomains if is_in_scope(s, scope)]

        # dnsx — validate DNS
        await _push_event(redis, scan_id, "tool_start", {"tool": "dnsx", "detail": f"{len(scoped_subs)} subdomains"})
        dnsx_out = os.path.join(recon_dir, "dnsx.txt")
        live_hosts = await tool_runner.run_dnsx(scoped_subs, dnsx_out)
        await _push_event(redis, scan_id, "tool_done", {"tool": "dnsx", "count": len(live_hosts)})

        # httpx — probe live hosts
        await _push_event(redis, scan_id, "tool_start", {"tool": "httpx", "detail": f"{len(live_hosts)} live hosts"})
        httpx_out = os.path.join(recon_dir, "httpx.jsonl")
        http_results = await tool_runner.run_httpx(live_hosts, httpx_out)
        live_urls = [r.get("url", "") for r in http_results if r.get("url")]
        await _push_event(redis, scan_id, "tool_done", {"tool": "httpx", "count": len(live_urls)})

        # Fallback: if httpx found nothing, seed from explicit scope URLs
        if not live_urls and scope.in_scope_urls:
            fallback = [u for u in scope.in_scope_urls if u.startswith("http")]
            if fallback:
                live_urls = fallback
                await _push_event(redis, scan_id, "tool_start", {
                    "tool": "httpx-fallback",
                    "detail": f"using {len(fallback)} explicit scope URLs",
                })
                await _push_event(redis, scan_id, "tool_done", {"tool": "httpx-fallback", "count": len(fallback)})

        # gau — deduplicate base domains to avoid running twice for *.example.com + example.com
        gau_urls: set[str] = set()
        seen_gau_bases: set[str] = set()
        for domain in scope.in_scope_domains:
            base = domain.lstrip("*.")
            if base in seen_gau_bases:
                continue
            seen_gau_bases.add(base)
            await _push_event(redis, scan_id, "tool_start", {"tool": "gau", "detail": base})
            gau_out = os.path.join(recon_dir, f"gau_{base}.txt")
            gau_results = await tool_runner.run_gau(base, gau_out)
            gau_urls.update(gau_results)
            await _push_event(redis, scan_id, "tool_done", {"tool": "gau", "count": len(gau_results)})

        # katana — crawl live URLs
        katana_urls = live_urls[:50] if live_urls else []
        await _push_event(redis, scan_id, "tool_start", {"tool": "katana", "detail": f"{len(katana_urls)} URLs"})
        katana_out = os.path.join(recon_dir, "katana.txt")
        crawled_urls = await tool_runner.run_katana(katana_urls, katana_out)
        await _push_event(redis, scan_id, "tool_done", {"tool": "katana", "count": len(crawled_urls)})

        # Merge all URLs, filter to scope
        all_target_urls = list(set(live_urls) | gau_urls | set(crawled_urls))
        all_target_urls = [u for u in all_target_urls if is_in_scope(u, scope)]

        async with aiofiles.open(os.path.join(recon_dir, "all_urls.txt"), "w") as f:
            await f.write("\n".join(sorted(all_target_urls)))

        await _push_event(redis, scan_id, "phase_done", {
            "phase": "active_recon",
            "live_hosts": len(live_hosts),
            "target_urls": len(all_target_urls),
        })

        # ── Phase 1.5: GitHub Dorking (passive, no target contact) ──────────
        await _push_event(redis, scan_id, "phase_start", {"phase": "github_dork"})
        await _push_event(redis, scan_id, "tool_start", {
            "tool": "github_dork",
            "detail": f"{len(scope.in_scope_domains)} domains",
        })
        github_out = os.path.join(scan_dir, "github_dork.jsonl")
        github_findings = await tool_runner.run_github_dork(
            scope.in_scope_domains, github_out, settings.github_token,
        )
        await _push_event(redis, scan_id, "tool_done", {
            "tool": "github_dork", "count": len(github_findings),
        })
        await _push_event(redis, scan_id, "phase_done", {
            "phase": "github_dork", "secrets": len(github_findings),
        })

        # ── Phase 2.5: Content Discovery (ffuf) ──────────────────────────────
        # Run on top 5 live hosts — finds hidden admin panels, backup files, .env etc.
        await _push_event(redis, scan_id, "phase_start", {"phase": "content_discovery"})

        ffuf_found_urls: list[str] = []
        ffuf_403_urls: list[str] = []

        ffuf_hosts = live_urls[:5] if live_urls else []
        if not ffuf_hosts and scope.in_scope_urls:
            ffuf_hosts = [u for u in scope.in_scope_urls if u.startswith("http")][:3]

        for host_url in ffuf_hosts:
            await _push_event(redis, scan_id, "tool_start", {
                "tool": "ffuf", "detail": host_url,
            })
            ffuf_out = os.path.join(scan_dir, f"ffuf_{len(ffuf_found_urls)}.json")
            results = await tool_runner.run_ffuf(host_url, "", ffuf_out)
            found = [f"{host_url.rstrip('/')}/{r['input']['FUZZ']}" for r in results if r.get("status") != 403]
            fbd_403 = [f"{host_url.rstrip('/')}/{r['input']['FUZZ']}" for r in results if r.get("status") == 403]
            ffuf_found_urls.extend(found)
            ffuf_403_urls.extend(fbd_403)
            await _push_event(redis, scan_id, "tool_done", {
                "tool": "ffuf", "count": len(results),
                "found": len(found), "forbidden": len(fbd_403),
            })

        # Add discovered URLs to the target pool (in-scope only)
        new_urls = [u for u in ffuf_found_urls if is_in_scope(u, scope)]
        all_target_urls = list(set(all_target_urls) | set(new_urls))

        await _push_event(redis, scan_id, "phase_done", {
            "phase": "content_discovery",
            "new_paths": len(new_urls),
            "forbidden": len(ffuf_403_urls),
        })

        # ── Phase 2.6: JS Secret Scanning ────────────────────────────────────
        await _push_event(redis, scan_id, "phase_start", {"phase": "js_scan"})

        # Collect all .js URLs from gau + katana output
        js_urls = [
            u for u in all_target_urls
            if u.endswith(".js") and not u.endswith(".min.js") and is_in_scope(u, scope)
        ]
        # Also grab .js from the full GAU output (not filtered by nuclei scorer)
        for u in list(gau_urls) + crawled_urls:
            if u.endswith(".js") and not u.endswith(".min.js") and is_in_scope(u, scope):
                if u not in js_urls:
                    js_urls.append(u)

        await _push_event(redis, scan_id, "tool_start", {
            "tool": "js_scanner", "detail": f"{len(js_urls)} JS files",
        })
        js_out = os.path.join(scan_dir, "js_secrets.jsonl")
        js_secrets = await tool_runner.run_js_scanner(js_urls, js_out)
        await _push_event(redis, scan_id, "tool_done", {
            "tool": "js_scanner", "count": len(js_secrets),
        })

        await _push_event(redis, scan_id, "phase_done", {
            "phase": "js_scan",
            "js_files": len(js_urls),
            "secrets_found": len(js_secrets),
        })

        # ── Phase 2.7: 403 Bypass Testing ────────────────────────────────────
        bypasses: list[dict] = []  # always initialized even if no 403s found
        if ffuf_403_urls:
            await _push_event(redis, scan_id, "phase_start", {"phase": "bypass_403"})
            await _push_event(redis, scan_id, "tool_start", {
                "tool": "403_bypass", "detail": f"{len(ffuf_403_urls)} forbidden endpoints",
            })
            bypass_out = os.path.join(scan_dir, "bypasses.jsonl")
            bypasses = await tool_runner.run_403_bypass(ffuf_403_urls, bypass_out)
            await _push_event(redis, scan_id, "tool_done", {
                "tool": "403_bypass", "count": len(bypasses),
            })
            await _push_event(redis, scan_id, "phase_done", {
                "phase": "bypass_403", "bypasses": len(bypasses),
            })

        # ── Phase 2.8: Parameter Discovery (arjun) ───────────────────────────
        # Run on top 5 parameterless interesting endpoints
        await _push_event(redis, scan_id, "phase_start", {"phase": "param_discovery"})

        PARAM_PATTERNS = ["/api/", "/v1/", "/v2/", "/graphql", "/search",
                          "/user", "/account", "/admin", "/auth", "/query"]
        param_targets = [
            u for u in all_target_urls
            if not "?" in u
            and is_in_scope(u, scope)
            and any(p in u for p in PARAM_PATTERNS)
        ][:5]

        arjun_params: dict[str, list[str]] = {}
        for pt_url in param_targets:
            await _push_event(redis, scan_id, "tool_start", {
                "tool": "arjun", "detail": pt_url,
            })
            arjun_out = os.path.join(scan_dir, f"arjun_{len(arjun_params)}.json")
            params = await tool_runner.run_arjun(pt_url, arjun_out)
            if params:
                arjun_params[pt_url] = params
                # Build URLs with discovered params → add to nuclei targets
                param_url = pt_url + "?" + "&".join(f"{p}=FUZZ" for p in params[:5])
                if is_in_scope(param_url, scope):
                    all_target_urls.append(param_url)
            await _push_event(redis, scan_id, "tool_done", {
                "tool": "arjun", "count": len(params),
            })

        await _push_event(redis, scan_id, "phase_done", {
            "phase": "param_discovery",
            "endpoints_tested": len(param_targets),
            "params_found": sum(len(v) for v in arjun_params.values()),
        })

        # ── Phase 2.9: CORS Checker ──────────────────────────────────────────
        await _push_event(redis, scan_id, "phase_start", {"phase": "cors_check"})
        await _push_event(redis, scan_id, "tool_start", {
            "tool": "cors_checker",
            "detail": f"{min(len(live_urls), 60)} live URLs",
        })
        cors_out = os.path.join(scan_dir, "cors.jsonl")
        cors_findings = await tool_runner.run_cors_checker(live_urls, cors_out)
        await _push_event(redis, scan_id, "tool_done", {
            "tool": "cors_checker", "count": len(cors_findings),
        })
        await _push_event(redis, scan_id, "phase_done", {
            "phase": "cors_check", "issues": len(cors_findings),
        })

        # ── Phase 2.10: Subdomain Takeover ────────────────────────────────────
        await _push_event(redis, scan_id, "phase_start", {"phase": "subdomain_takeover"})
        await _push_event(redis, scan_id, "tool_start", {
            "tool": "subdomain_takeover",
            "detail": f"{min(len(list(all_subdomains)), 200)} subdomains",
        })
        takeover_out = os.path.join(scan_dir, "takeovers.jsonl")
        takeover_findings = await tool_runner.run_subdomain_takeover(
            list(all_subdomains), takeover_out
        )
        await _push_event(redis, scan_id, "tool_done", {
            "tool": "subdomain_takeover", "count": len(takeover_findings),
        })
        await _push_event(redis, scan_id, "phase_done", {
            "phase": "subdomain_takeover", "vulnerable": len(takeover_findings),
        })

        # ── Phase 3: Nuclei scan ──────────────────────────────────────────────
        # Smart URL selection: nuclei works best on a focused set of high-value targets.
        # Too many URLs (3000+) makes scans take hours; cap at 500 prioritised URLs.
        nuclei_urls = _select_nuclei_targets(all_target_urls, live_urls, max_urls=500)

        await _push_event(redis, scan_id, "phase_start", {"phase": "nuclei_scan"})
        await _push_event(redis, scan_id, "tool_start", {
            "tool": "nuclei",
            "detail": f"{len(nuclei_urls)} targets (of {len(all_target_urls)} total)",
        })

        nuclei_out = os.path.join(scan_dir, "nuclei.jsonl")

        # Run nuclei with a concurrent progress ticker so the SSE stream stays alive.
        # Without this, the 10-minute idle timeout disconnects the browser mid-scan.
        async def _nuclei_progress_ticker():
            elapsed = 0
            while True:
                await asyncio.sleep(30)
                elapsed += 30
                await _push_event(redis, scan_id, "nuclei_progress", {
                    "elapsed_s": elapsed,
                    "targets": len(nuclei_urls),
                })

        ticker = asyncio.create_task(_nuclei_progress_ticker())
        try:
            raw_findings = await tool_runner.run_nuclei(nuclei_urls, nuclei_out, scope)
        finally:
            ticker.cancel()

        await _push_event(redis, scan_id, "phase_done", {
            "phase": "nuclei_scan",
            "raw_findings": len(raw_findings),
        })

        # ── Phase 4: Filter & validate ────────────────────────────────────────
        await _push_event(redis, scan_id, "phase_start", {"phase": "filtering"})

        approved_count = 0
        rejected_count = 0

        # Convert JS secrets → Finding objects and add to the evaluation queue
        for secret in js_secrets:
            raw_findings.append({
                "_source": "js_scanner",
                "info": {
                    "name": f"Exposed Secret in JavaScript: {secret['secret_type']}",
                    "severity": secret["severity"],
                    "tags": ["token-disclosure", "exposure"],
                },
                "matched-at": secret["url"],
                "type": "token-disclosure",
                "extracted-results": [secret["match"]],
                "_context": secret["context"],
                "_secret_type": secret["secret_type"],
            })

        # Convert 403 bypasses → Finding objects
        for bypass in bypasses:
            raw_findings.append({
                "_source": "403_bypass",
                "info": {
                    "name": f"403 Bypass via {bypass['bypass_type'].title()} Manipulation",
                    "severity": bypass["severity"],
                    "tags": ["auth-bypass", "access-control"],
                },
                "matched-at": bypass["url"],
                "type": "auth-bypass",
                "_bypass_payload": bypass["payload"],
                "_bypass_status": bypass["status"],
            })

        # Convert CORS findings → Finding objects
        for cors in cors_findings:
            raw_findings.append({
                "_source": "cors_checker",
                "info": {
                    "name": f"CORS Misconfiguration — {cors['attack_type'].replace('_', ' ').title()}",
                    "severity": cors["severity"],
                    "tags": ["cors", "misconfig"],
                    "description": cors.get("impact", ""),
                },
                "matched-at": cors["url"],
                "type": "cors-misconfig",
                "_origin_sent": cors["origin_sent"],
                "_acao": cors["acao_header"],
                "_acac": cors["acac_header"],
            })

        # Convert subdomain takeover findings → Finding objects
        for takeover in takeover_findings:
            raw_findings.append({
                "_source": "subdomain_takeover",
                "info": {
                    "name": f"Subdomain Takeover — {takeover['subdomain']} → {takeover['provider']}",
                    "severity": takeover["severity"],
                    "tags": ["subdomain-takeover", "misconfig"],
                    "description": takeover.get("impact", ""),
                },
                "matched-at": f"https://{takeover['subdomain']}",
                "type": "subdomain-takeover",
                "_provider": takeover["provider"],
                "_fingerprint": takeover["fingerprint"],
                "_evidence_url": takeover.get("evidence_url", ""),
            })

        # Convert GitHub dork findings → Finding objects
        for gh in github_findings:
            raw_findings.append({
                "_source": "github_dork",
                "info": {
                    "name": f"Exposed {gh['secret_type']} in GitHub Repository",
                    "severity": gh["severity"],
                    "tags": ["token-disclosure", "exposure", "github"],
                    "description": (
                        f"Secret found in {gh['repo']} at {gh['file_path']}. "
                        f"Query: {gh['query']}"
                    ),
                },
                "matched-at": gh["html_url"],
                "type": "token-disclosure",
                "_repo": gh["repo"],
                "_file_path": gh["file_path"],
                "_snippet": gh["snippet"],
                "_secret_type": gh["secret_type"],
            })

        for raw in raw_findings:
            finding = _nuclei_to_finding(raw, job)

            await _push_event(redis, scan_id, "finding_evaluating", {
                "title": finding.title,
                "url": finding.url,
                "vuln_type": finding.vuln_type,
            })

            passed, reason = await finding_filter.run_all_layers(
                finding, scope, program.raw_text
            )

            if passed:
                approved_count += 1
                finding_path = os.path.join(finding_dir, "filtered", f"{finding.id}.json")
                async with aiofiles.open(finding_path, "w") as f:
                    await f.write(finding.model_dump_json(indent=2))

                await _push_event(redis, scan_id, "finding_approved", {
                    "id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "reason": reason,
                })

                # Phase 5: Generate report for this finding
                try:
                    report = await report_generator.generate(finding, scope)
                    job.reports_count += 1
                    await _push_event(redis, scan_id, "report_generated", {
                        "finding_id": finding.id,
                        "report_id": report.id,
                        "title": report.title,
                    })
                except Exception as e:
                    await _push_event(redis, scan_id, "report_error", {
                        "finding_id": finding.id,
                        "error": str(e),
                    })
            else:
                rejected_count += 1
                # Save rejected finding with reason for review
                rejected_data = {**json.loads(finding.model_dump_json()), "rejection_reason": reason}
                rej_path = os.path.join(finding_dir, "rejected", f"{finding.id}.json")
                async with aiofiles.open(rej_path, "w") as f:
                    await f.write(json.dumps(rejected_data, indent=2))

                await _push_event(redis, scan_id, "finding_rejected", {
                    "title": finding.title,
                    "reason": reason,
                })

        job.findings_count = approved_count
        job.status = ScanStatus.done
        job.finished_at = datetime.utcnow()
        await _save_job(job, program_id)

        await _push_event(redis, scan_id, "scan_done", {
            "approved": approved_count,
            "rejected": rejected_count,
            "reports": job.reports_count,
        })

    except Exception as e:
        job.status = ScanStatus.failed
        job.finished_at = datetime.utcnow()
        await _save_job(job, program_id)
        await _push_event(redis, scan_id, "scan_error", {"error": str(e)})
        raise
    finally:
        if redis:
            await redis.aclose()


def _nuclei_to_finding(raw: dict, job: ScanJob) -> Finding:
    """Convert nuclei JSON output line to Finding model."""
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


# ── routes ────────────────────────────────────────────────────────────────────

@router.post("/start", response_model=ApiResponse)
async def start_scan(body: ScanCreate):
    """
    Start a scan job for an approved plan.
    Returns scan job ID immediately; scan runs in background.
    """
    # Verify program exists and has usable scope
    prog_file = os.path.join(WORKSPACE, body.program_id, "program.json")
    if not os.path.exists(prog_file):
        raise HTTPException(status_code=404, detail=f"Program '{body.program_id}' not found")

    program = await _load_scope_and_program(body.program_id)
    if not program.scope or not program.scope.in_scope_domains:
        raise HTTPException(
            status_code=400,
            detail="Scope has no in-scope domains. Claude could not extract targets from the program text. "
                   "Re-create the program with a complete HackerOne scope section that lists specific domains.",
        )

    job = ScanJob(
        id=str(uuid.uuid4()),
        program_id=body.program_id,
        status=ScanStatus.pending,
    )

    await _save_job(job, body.program_id)

    # Launch scan as a free asyncio task (not a FastAPI BackgroundTask) so it
    # survives across uvicorn hot-reloads and doesn't block shutdown.
    asyncio.create_task(_run_scan(job, body.approved_plan))

    return ApiResponse(success=True, data=json.loads(job.model_dump_json()))


@router.get("/{program_id}/{scan_id}/stream")
async def stream_scan(program_id: str, scan_id: str):
    """
    SSE stream of live scan output.
    Reads events from Redis list for this scan_id.
    Detects zombie scans (interrupted mid-run) and emits scan_error rather than
    waiting 2 hours for events that will never arrive.
    """
    async def event_generator():
        redis = await _get_redis()
        cursor = 0
        idle_ticks = 0
        last_event_type: str = ""

        while True:
            if redis:
                events = await redis.lrange(f"scan:{scan_id}:events", cursor, cursor + 49)
                if events:
                    idle_ticks = 0
                    for raw_event in events:
                        cursor += 1
                        parsed = json.loads(raw_event)
                        last_event_type = parsed["type"]
                        yield {"event": last_event_type, "data": json.dumps(parsed["data"])}

                    # Check if scan is done
                    if last_event_type in ("scan_done", "scan_error"):
                        if redis:
                            await redis.aclose()
                        return
                else:
                    idle_ticks += 1
                    # Yield heartbeat to keep connection alive
                    yield {"event": "heartbeat", "data": "{}"}

                    # ── Zombie scan detection ────────────────────────────────
                    # After 30 idle seconds with no new events, and the last event
                    # was NOT a terminal event, check if the scan was interrupted
                    # (e.g. by a server restart mid-nuclei-run).
                    # Compare the timestamp of the last Redis event against now.
                    if idle_ticks == 30 and last_event_type not in ("scan_done", "scan_error", ""):
                        try:
                            last_raw = await redis.lindex(f"scan:{scan_id}:events", -1)
                            if last_raw:
                                last_ts_str = json.loads(last_raw).get("ts", "")
                                if last_ts_str:
                                    from datetime import timezone
                                    last_ts = datetime.fromisoformat(last_ts_str)
                                    age_s = (datetime.now(timezone.utc) - last_ts.replace(tzinfo=timezone.utc)).total_seconds()
                                    if age_s > 60:
                                        # Last event is >60s old and nothing new → zombie
                                        await _push_event(redis, scan_id, "scan_error", {
                                            "error": "Scan was interrupted (server restart or crash). "
                                                     "Please start a new scan."
                                        })
                                        yield {"event": "scan_error", "data": json.dumps({
                                            "error": "Scan was interrupted (server restart or crash). "
                                                     "Please start a new scan."
                                        })}
                                        await redis.aclose()
                                        return
                        except Exception:
                            pass

                    if idle_ticks > 7200:  # 2 hours of silence → give up
                        if redis:
                            await redis.aclose()
                        return
            else:
                yield {"event": "error", "data": json.dumps({"message": "Redis unavailable"})}
                return

            await asyncio.sleep(1)

    return EventSourceResponse(event_generator())


@router.get("/{program_id}/{scan_id}", response_model=ApiResponse)
async def get_scan(program_id: str, scan_id: str):
    """Get scan job status and summary."""
    job = await _load_job(program_id, scan_id)
    return ApiResponse(success=True, data=json.loads(job.model_dump_json()))


@router.get("/{program_id}/{scan_id}/findings", response_model=ApiResponse)
async def get_findings(program_id: str, scan_id: str):
    """
    Get all filtered, validated findings for a scan.
    Returns findings from workspace/{program}/findings/filtered/
    """
    finding_dir = os.path.join(_finding_dir(program_id), "filtered")
    if not os.path.exists(finding_dir):
        return ApiResponse(success=True, data={"findings": []})

    findings = []
    for entry in os.scandir(finding_dir):
        if entry.name.endswith(".json"):
            async with aiofiles.open(entry.path, encoding="utf-8") as f:
                data = json.loads(await f.read())
            # Filter to this scan
            if data.get("scan_id") == scan_id:
                findings.append(data)

    findings.sort(key=lambda f: f.get("created_at", ""), reverse=True)
    return ApiResponse(success=True, data={"findings": findings})
