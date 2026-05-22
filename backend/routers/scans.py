import asyncio
import json
import os
import re
import uuid
from datetime import datetime
from urllib.parse import urlparse

# Matches credentials embedded in URL paths like:
#   /:user@domain.com:Password123   (path-style, from GAU history)
#   /user:password@host/path       (RFC-3986 userinfo in path — malformed but common)
_CRED_IN_PATH_RE = re.compile(
    r'(?:^|/)'                          # start of path segment
    r':?'                               # optional leading colon
    r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+'  # email-like username
    r':'                                # separator
    r'[^/\s@]{6,}',                    # password (≥6 chars, no space/slash)
    re.IGNORECASE,
)

# Matches interesting API path SEGMENTS (not substrings of longer words).
# Keyword must be a complete path segment: followed by / or end of string only.
# Dot is intentionally excluded — /user.gender, /user.email are doc pages, not endpoints.
# Examples:  /api/v1 ✓   /auth/login ✓   /login ✓
#            /authors/ ✗   /users/ ✗   /user.gender ✗   /user.email ✗
_ARJUN_PATH_RE = re.compile(
    r'/(?:api|v[123456]|graphql|search|user|account|admin|auth|query|login|register|oauth|token|payment)'
    r'(?=/|$)',   # followed by / or end of string — NOT dot, NOT alphanumeric
    re.IGNORECASE,
)

import aiofiles
import redis.asyncio as aioredis
from fastapi import APIRouter, HTTPException, Request
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


def _select_ffuf_targets(live_urls: list[str], max_hosts: int = 5) -> list[str]:
    """
    Pick the best base hosts for directory fuzzing.
    Prefer API/admin subdomains on standard ports; skip CDN/media/CS hosts.
    """
    from urllib.parse import urlparse

    # Subdomain name patterns that are interesting for directory fuzzing
    INTERESTING_SUB = (
        "api", "admin", "portal", "dashboard", "dev", "staging", "internal",
        "test", "beta", "app", "manage", "console", "panel", "monitor",
        "login", "auth", "upload", "backend", "service", "services",
    )
    # Subdomain/path patterns that indicate CDN, media, or delivery hosts
    CDN_SKIP = (
        "edge", "cdn", "rtm", "streaming", "delivery", "media", "img",
        "static", "live", "video", "cam", "thumb", "photo", "image",
        "archive", "mirror", "relay",
    )

    def _host_score(url: str) -> int:
        try:
            p = urlparse(url)
        except Exception:
            return -999
        host = p.hostname or ""
        subdomain = host.split(".")[0].lower() if "." in host else host.lower()

        # Skip clear CDN/media delivery nodes
        if any(c in host.lower() for c in CDN_SKIP):
            return -999

        score = 0

        # Prefer HTTPS
        if p.scheme == "https":
            score += 20
        # Prefer standard ports (no explicit port = 443/80)
        if not p.port:
            score += 15
        elif p.port in (80, 443):
            score += 10
        else:
            score -= 20  # non-standard port (8443, 8080, etc.)

        # Boost interesting subdomains
        if any(kw == subdomain or subdomain.startswith(kw) for kw in INTERESTING_SUB):
            score += 40

        return score

    # Deduplicate by base host (scheme+netloc) — one entry per host
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

    try:
        os.makedirs(scan_dir, exist_ok=True)
        os.makedirs(os.path.join(finding_dir, "filtered"), exist_ok=True)
        os.makedirs(os.path.join(finding_dir, "rejected"), exist_ok=True)
    except OSError as _io_err:
        # Docker Desktop / WSL2 volume IO error — surface a clear message
        await _push_event(
            await _get_redis(), scan_id, "scan_error",
            {"error": (
                f"Workspace volume IO error (errno {_io_err.errno}). "
                "Restart Docker Desktop and try again."
            )},
        )
        return

    redis = await _get_redis()

    try:
        # Update job status
        job.status = ScanStatus.running
        job.started_at = datetime.utcnow()
        await _save_job(job, program_id)

        # ── Delta scanning: load baseline from previous scan ─────────────────
        # Comparing current scan against the previous one lets us highlight NEW
        # subdomains / endpoints that appeared since last run — first-mover advantage.
        _delta_file = os.path.join(WORKSPACE, program_id, "scan_history.json")
        _prev_subdomains: set[str] = set()
        _prev_live_urls: set[str] = set()
        _prev_scan_date: str = ""
        if os.path.exists(_delta_file):
            try:
                import aiofiles as _af
                async with _af.open(_delta_file, encoding="utf-8") as _df:
                    _prev_data = json.loads(await _df.read())
                _prev_subdomains = set(_prev_data.get("subdomains", []))
                _prev_live_urls = set(_prev_data.get("live_urls", []))
                _prev_scan_date = _prev_data.get("scan_date", "")
                await _push_event(redis, scan_id, "delta_baseline", {
                    "prev_scan_date": _prev_scan_date,
                    "prev_subdomains": len(_prev_subdomains),
                    "prev_live_urls": len(_prev_live_urls),
                })
            except Exception:
                pass  # No valid history — first scan for this program

        program = await _load_scope_and_program(program_id)
        scope = program.scope

        # ── Pipeline adaptation: tailor phases to program type ────────────────
        # mobile / blockchain / source_code programs have no live web surface to crawl —
        # skip heavy web-crawl phases and focus on passive recon + nuclei + dorking.
        # API-only programs skip deep HTML crawling but benefit from arjun + CORS checks.
        notes_lower = (scope.notes or "").lower()
        prog_type = (scope.program_type or "web").lower()

        do_katana  = prog_type in ("web", "api")      # JS crawling useless for mobile/blockchain
        do_ffuf    = prog_type == "web"                # dir-fuzzing irrelevant for pure APIs
        do_arjun   = prog_type in ("web", "api")
        arjun_max  = 10 if prog_type == "api" else 5   # more param targets for API programs

        # Skip nuclei if the program explicitly bans automated scanners
        _no_scan_keywords = [
            "no automated scanner", "no automated scanning", "no scanners",
            "manual testing only", "no automated tools", "do not use automated",
            "do not run automated", "automated tools are not allowed",
        ]
        do_nuclei = not any(kw in notes_lower for kw in _no_scan_keywords)

        await _push_event(redis, scan_id, "pipeline_config", {
            "program_type": prog_type,
            "do_katana": do_katana,
            "do_ffuf": do_ffuf,
            "do_arjun": do_arjun,
            "do_nuclei": do_nuclei,
        })

        await _push_event(redis, scan_id, "phase_start", {"phase": "passive_recon"})

        # ── Phase 1: Passive recon ────────────────────────────────────────────
        all_subdomains: set[str] = set()
        all_urls: set[str] = set()

        # Deduplicate to unique apex domains before running passive recon.
        # Programs like Coupang Taiwan list 45 explicit subdomains — running
        # run_all_passive() on all of them sequentially would take 22+ minutes
        # (45 domains × 5 API sources × 30s timeout).
        # Strategy: extract unique apex domains (last two labels) and cap at 5.
        # e.g. payment.tw.coupang.com → tw.coupang.com
        #      shop.tw.coupang.com    → tw.coupang.com  (same apex, skip)
        #      tw.coupangcorp.com     → tw.coupangcorp.com (different apex, keep)
        def _apex(domain: str) -> str:
            parts = domain.lstrip("*.").split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lstrip("*.")

        seen_apexes: set[str] = set()
        passive_domains: list[str] = []
        for _d in scope.in_scope_domains:
            _base = _d.lstrip("*.")
            _apex_d = _apex(_base)
            if _apex_d not in seen_apexes:
                seen_apexes.add(_apex_d)
                passive_domains.append(_base)
            if len(passive_domains) >= 5:  # hard cap — passive recon has no scanner value beyond 5
                break

        await _push_event(redis, scan_id, "pipeline_config", {
            "passive_domains": passive_domains,
            "total_scope_domains": len(scope.in_scope_domains),
        })

        # Run all passive recon domains in PARALLEL — no reason to wait for each
        passive_results = await asyncio.gather(
            *[passive_recon.run_all_passive(d) for d in passive_domains],
            return_exceptions=True,
        )
        for passive in passive_results:
            if isinstance(passive, Exception):
                continue
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

        # Phase 2.1: nmap — find web services on non-standard ports
        # Runs on up to 100 dnsx-confirmed live hosts; adds "hostname:port" pairs to httpx targets.
        # Services on ports 8080/8443/3000/5000 are often less hardened than the
        # primary 443 endpoint and are easy to miss without port scanning.
        # CDN-aware: run_nmap pre-resolves hostnames so CDN IPs (Cloudflare, Fastly)
        # are expanded back to all hostnames sharing that IP → correct SNI/Host routing.
        await _push_event(redis, scan_id, "tool_start", {
            "tool": "nmap",
            "detail": f"non-standard web ports on {min(len(live_hosts), 100)} hosts",
        })
        nmap_out = os.path.join(recon_dir, "nmap.gnmap")
        nmap_endpoints = await tool_runner.run_nmap(live_hosts, nmap_out)
        await _push_event(redis, scan_id, "tool_done", {
            "tool": "nmap", "count": len(nmap_endpoints),
        })

        detected_techs: set[str] = set()  # populated after httpx completes

        # httpx — probe live hosts + always include explicit scope URLs so we get
        # at least metadata for known-good targets even if all subfinder hosts fail.
        # (Most subfinder subdomains resolve in DNS but have no web service → 0 httpx results)
        explicit_scope_urls = [u for u in (scope.in_scope_urls or []) if u.startswith("http")]
        httpx_targets = list(live_hosts)
        # Add nmap-discovered non-standard ports
        for ep in nmap_endpoints:
            if ep not in httpx_targets:
                httpx_targets.append(ep)
        for _eu in explicit_scope_urls:
            if _eu not in httpx_targets:
                httpx_targets.append(_eu)

        await _push_event(redis, scan_id, "tool_start", {"tool": "httpx", "detail": f"{len(httpx_targets)} hosts"})
        httpx_out = os.path.join(recon_dir, "httpx.jsonl")
        http_results = await tool_runner.run_httpx(httpx_targets, httpx_out)
        live_urls = [r.get("url", "") for r in http_results if r.get("url")]
        await _push_event(redis, scan_id, "tool_done", {"tool": "httpx", "count": len(live_urls)})

        # Extract tech stack from httpx results for smarter nuclei CVE targeting
        detected_techs: set[str] = tool_runner.extract_tech_stack(http_results)
        if detected_techs:
            await _push_event(redis, scan_id, "tech_detected", {
                "techs": sorted(detected_techs),
            })

        # Fallback 1: httpx found nothing → seed from explicit scope URLs
        if not live_urls and explicit_scope_urls:
            live_urls = explicit_scope_urls
            await _push_event(redis, scan_id, "tool_start", {
                "tool": "httpx-fallback",
                "detail": f"using {len(explicit_scope_urls)} explicit scope URLs",
            })
            await _push_event(redis, scan_id, "tool_done", {
                "tool": "httpx-fallback", "count": len(explicit_scope_urls),
            })

        # Fallback 2: still nothing → generate URLs from in_scope_domains directly.
        # Covers programs that only specify *.example.com (no explicit URLs) and
        # where all subfinder-discovered subdomains have no HTTP service.
        if not live_urls:
            generated: list[str] = []
            for _d in scope.in_scope_domains[:3]:
                _base = _d.lstrip("*.")
                for _prefix in ("", "www.", "api.", "app.", "dashboard.", "portal."):
                    generated.append(f"https://{_prefix}{_base}")
            # Probe these candidates so we get real status codes, not guesses
            _gen_httpx_out = os.path.join(recon_dir, "httpx_gen.jsonl")
            await _push_event(redis, scan_id, "tool_start", {
                "tool": "httpx-gen-fallback",
                "detail": f"probing {len(generated)} generated domain URLs",
            })
            _gen_results = await tool_runner.run_httpx(generated, _gen_httpx_out)
            _gen_live = [r.get("url", "") for r in _gen_results if r.get("url")]
            if _gen_live:
                live_urls = _gen_live
            else:
                # Nothing responded — use generated list as plain seeds (gau/katana still benefit)
                live_urls = generated
            await _push_event(redis, scan_id, "tool_done", {
                "tool": "httpx-gen-fallback", "count": len(live_urls),
            })

        # gau — run on unique apex domains only (same dedup logic as passive recon).
        # Programs with 45 explicit subdomains should not trigger 45 gau runs —
        # gau queries by apex anyway, so tw.coupang.com covers all its subdomains.
        gau_urls: set[str] = set()
        seen_gau_apexes: set[str] = set()
        gau_domains_run: list[str] = []
        for domain in scope.in_scope_domains:
            base = domain.lstrip("*.")
            apex_d = _apex(base)
            if apex_d in seen_gau_apexes:
                continue
            seen_gau_apexes.add(apex_d)
            gau_domains_run.append(base)
            if len(gau_domains_run) >= 5:  # cap — beyond 5 apex domains gau adds noise
                break

        for gau_domain in gau_domains_run:
            await _push_event(redis, scan_id, "tool_start", {"tool": "gau", "detail": gau_domain})
            gau_out = os.path.join(recon_dir, f"gau_{gau_domain.replace('.', '_')}.txt")
            gau_results = await tool_runner.run_gau(gau_domain, gau_out)
            gau_urls.update(gau_results)
            await _push_event(redis, scan_id, "tool_done", {"tool": "gau", "count": len(gau_results)})

        # katana — crawl live URLs (skip for mobile/blockchain/source_code programs)
        if do_katana:
            katana_urls = live_urls[:50] if live_urls else []
            await _push_event(redis, scan_id, "tool_start", {"tool": "katana", "detail": f"{len(katana_urls)} URLs"})
            katana_out = os.path.join(recon_dir, "katana.txt")
            crawled_urls = await tool_runner.run_katana(katana_urls, katana_out)
            await _push_event(redis, scan_id, "tool_done", {"tool": "katana", "count": len(crawled_urls)})
        else:
            crawled_urls = []
            await _push_event(redis, scan_id, "tool_skip", {
                "tool": "katana", "reason": f"program_type={prog_type} — JS crawling not applicable",
            })

        # Merge all URLs, filter to scope, cap at 15k to keep later phases manageable
        all_target_urls = list(set(live_urls) | gau_urls | set(crawled_urls))
        all_target_urls = [u for u in all_target_urls if is_in_scope(u, scope)]
        if len(all_target_urls) > 15_000:
            # Prioritise shorter URLs (more likely to be API endpoints) before truncating
            all_target_urls.sort(key=lambda u: len(u))
            all_target_urls = all_target_urls[:15_000]

        # ── Credential-in-URL detection (from GAU) ───────────────────────────
        # Two patterns:
        #   1. RFC-3986 userinfo: https://user:password@host/  → urlparse catches this
        #   2. Path-embedded:    https://host/:email@dom:Pass  → regex catches this
        cred_urls: list[dict] = []
        _seen_cred_hosts: set[str] = set()
        for _raw_url in gau_urls:
            try:
                _p = urlparse(_raw_url)
                _host = _p.hostname or ""
                if not _host or _host in _seen_cred_hosts:
                    continue

                if _p.password:
                    # Standard RFC-3986 userinfo format
                    _seen_cred_hosts.add(_host)
                    cred_urls.append({
                        "url": _raw_url,
                        "username": _p.username or "",
                        "password": _p.password,
                        "host": _host,
                        "source": "userinfo",
                    })
                elif _CRED_IN_PATH_RE.search(_p.path):
                    # Credentials embedded in path (e.g. /:user@domain.com:Passw0rd)
                    _seen_cred_hosts.add(_host)
                    cred_urls.append({
                        "url": _raw_url,
                        "username": "",  # can't reliably extract without full parse
                        "password": "",
                        "host": _host,
                        "source": "path_embedded",
                    })
            except Exception:
                pass

        async with aiofiles.open(os.path.join(recon_dir, "all_urls.txt"), "w") as f:
            await f.write("\n".join(sorted(all_target_urls)))

        await _push_event(redis, scan_id, "phase_done", {
            "phase": "active_recon",
            "live_hosts": len(live_hosts),
            "target_urls": len(all_target_urls),
            **({"cred_urls": len(cred_urls)} if cred_urls else {}),
        })

        # ── Delta: compare with previous scan ────────────────────────────────
        if _prev_subdomains or _prev_live_urls:
            _new_subs = sorted(all_subdomains - _prev_subdomains)
            _new_urls = sorted(set(live_urls) - _prev_live_urls)
            if _new_subs or _new_urls:
                await _push_event(redis, scan_id, "delta_new_surface", {
                    "new_subdomains_count": len(_new_subs),
                    "new_subdomains": _new_subs[:20],
                    "new_live_urls_count": len(_new_urls),
                    "new_live_urls": _new_urls[:10],
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
        # Skipped for API/mobile/blockchain programs where directory fuzzing adds no value.
        await _push_event(redis, scan_id, "phase_start", {"phase": "content_discovery"})

        ffuf_found_urls: list[str] = []
        ffuf_403_urls: list[str] = []

        if do_ffuf:
            ffuf_hosts = _select_ffuf_targets(live_urls, max_hosts=5)
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
        else:
            await _push_event(redis, scan_id, "phase_done", {
                "phase": "content_discovery",
                "skipped": True,
                "reason": f"program_type={prog_type}",
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

        # Pre-filter: skip known-public client-side key patterns that are intentionally
        # embedded in JS. Algolia search-only keys, Next.js NEXT_PUBLIC_ vars, and
        # similar patterns are by design public-facing and not security vulnerabilities.
        # Filtering here avoids wasting L2 AI calls on guaranteed-reject findings.
        _JS_PUBLIC_CTX = (
            "algolia", "search-api-key", "searchapikey",
            "next_public_", "react_app_", "vite_public_",
            "gtm-", "googletagmanager", "ga-measurement",
        )
        _js_pre_filtered = 0
        _js_kept = []
        for _s in js_secrets:
            _ctx_lower = (_s.get("context", "") + " " + _s.get("match", "")).lower()
            if any(_p in _ctx_lower for _p in _JS_PUBLIC_CTX):
                _js_pre_filtered += 1
            else:
                _js_kept.append(_s)
        js_secrets = _js_kept

        await _push_event(redis, scan_id, "phase_done", {
            "phase": "js_scan",
            "js_files": len(js_urls),
            "secrets_found": len(js_secrets),
            **({"pre_filtered_public_keys": _js_pre_filtered} if _js_pre_filtered else {}),
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
        # Run on top N parameterless interesting endpoints (N is larger for API programs).
        await _push_event(redis, scan_id, "phase_start", {"phase": "param_discovery"})

        STATIC_EXTS = {".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                       ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
                       ".txt", ".xml", ".yaml", ".yml", ".json", ".lock",
                       ".pdf", ".zip", ".gz", ".tar", ".md", ".csv",
                       ".html", ".htm", ".min.html", ".min.htm"}  # HTML pages have no query params

        # Static directory path segments — arjun has no value testing assets/static dirs
        _STATIC_PATH_SEGS = frozenset({
            "static", "assets", "vendor", "dist", "build", "public",
            "images", "img", "fonts", "media", "css", "views",
        })

        arjun_params: dict[str, list[str]] = {}

        if do_arjun:
            param_targets: list[str] = []
            for _u in all_target_urls:
                if "?" in _u or not is_in_scope(_u, scope):
                    continue
                try:
                    _parsed_u = urlparse(_u)
                    _path = _parsed_u.path.lower()
                except Exception:
                    continue
                # Skip directory listings (path ends with /)
                if _path.endswith("/") and _path != "/":
                    continue
                # Skip static / asset files — arjun has no business scanning them
                if any(_path.endswith(_ext) for _ext in STATIC_EXTS):
                    continue
                # Skip paths that pass through known static asset directories
                # e.g. /login/static/views/mfa.html, /login/static/css/images/
                _raw_parts = [p for p in _path.split("/") if p]
                if any(seg in _STATIC_PATH_SEGS for seg in _raw_parts[:-1]):
                    continue
                # Skip URLs with duplicate path segments — these are crawler artifacts
                # e.g. /customer_support/API/register/API/register/API/logging/ from katana
                # following relative hrefs recursively on SPAs.
                if len(_raw_parts) != len(set(_raw_parts)):
                    continue
                # Skip URLs where a path segment contains '=' — these are gau artifacts
                # where query strings were incorrectly merged into the URL path
                # (e.g. /v1/messagesr= from ?r=... losing its '?').
                if any("=" in part for part in _raw_parts):
                    continue
                # Only match within the FIRST TWO path segments.
                # Real API endpoints live at /api/..., /auth/..., /oauth/...
                # Deep content pages like /legal/modernslaverystatement/api/ are not APIs.
                _parts = _raw_parts
                _path_prefix = "/" + "/".join(_parts[:2])
                if _ARJUN_PATH_RE.search(_path_prefix):
                    param_targets.append(_u)
                if len(param_targets) >= arjun_max:
                    break

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
        else:
            await _push_event(redis, scan_id, "phase_done", {
                "phase": "param_discovery",
                "skipped": True,
                "reason": f"program_type={prog_type}",
            })

        # ── Phase 2.8.5: XSS Scan (dalfox on arjun-discovered params) ──────────
        # Only runs when arjun found actual injectable parameters — no arjun params
        # means no URLs to fuzz, so dalfox is skipped entirely.
        dalfox_findings: list[dict] = []
        if arjun_params:
            await _push_event(redis, scan_id, "phase_start", {"phase": "xss_scan"})
            for _xss_base, _xss_params in list(arjun_params.items())[:3]:  # cap at 3 endpoints
                _xss_url = _xss_base + "?" + "&".join(f"{p}=test" for p in _xss_params[:5])
                await _push_event(redis, scan_id, "tool_start", {
                    "tool": "dalfox",
                    "detail": f"{_xss_base} ({len(_xss_params)} params)",
                })
                _dalfox_out = os.path.join(scan_dir, f"dalfox_{len(dalfox_findings)}.json")
                _dalfox_results = await tool_runner.run_dalfox(_xss_url, _xss_params, _dalfox_out)
                dalfox_findings.extend(_dalfox_results)
                await _push_event(redis, scan_id, "tool_done", {
                    "tool": "dalfox", "count": len(_dalfox_results),
                })
            await _push_event(redis, scan_id, "phase_done", {
                "phase": "xss_scan", "findings": len(dalfox_findings),
            })

        # ── Phase 2.9: CORS Checker ──────────────────────────────────────────
        await _push_event(redis, scan_id, "phase_start", {"phase": "cors_check"})
        await _push_event(redis, scan_id, "tool_start", {
            "tool": "cors_checker",
            "detail": f"{min(len(live_urls), 120)} live URLs",
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

        # ── Phase 2.11: Email Security (SPF / DMARC) ─────────────────────────
        # Pure DNS — no active scanning, no rate limits, no WAF concerns.
        # Missing/weak DMARC is a frequent Medium finding on H1.
        await _push_event(redis, scan_id, "phase_start", {"phase": "email_security"})
        await _push_event(redis, scan_id, "tool_start", {
            "tool": "email_security",
            "detail": f"{len(scope.in_scope_domains)} domains",
        })
        email_out = os.path.join(scan_dir, "email_security.jsonl")
        email_findings = await tool_runner.run_email_security(
            scope.in_scope_domains, email_out
        )
        await _push_event(redis, scan_id, "tool_done", {
            "tool": "email_security", "count": len(email_findings),
        })
        await _push_event(redis, scan_id, "phase_done", {
            "phase": "email_security", "issues": len(email_findings),
        })

        # ── Phase 2.12: Swagger / OpenAPI Discovery ───────────────────────────
        # Exposed API specs are Medium findings AND map the full API surface
        # so subsequent nuclei/arjun passes have more precise targets.
        await _push_event(redis, scan_id, "phase_start", {"phase": "swagger_discovery"})
        await _push_event(redis, scan_id, "tool_start", {
            "tool": "swagger_discovery",
            "detail": f"{len(live_urls)} live hosts",
        })
        swagger_out = os.path.join(scan_dir, "swagger.jsonl")
        swagger_findings = await tool_runner.run_swagger_discovery(live_urls, swagger_out)
        # If specs found, extract their API paths → add to nuclei target pool
        for _sw in swagger_findings:
            for _api_path in _sw.get("sample_paths", []):
                _full = _sw["base_url"].rstrip("/") + _api_path
                if is_in_scope(_full, scope) and _full not in all_target_urls:
                    all_target_urls.append(_full)
        await _push_event(redis, scan_id, "tool_done", {
            "tool": "swagger_discovery", "count": len(swagger_findings),
        })
        await _push_event(redis, scan_id, "phase_done", {
            "phase": "swagger_discovery",
            "specs_found": len(swagger_findings),
            "new_endpoints": sum(s.get("endpoints_count", 0) for s in swagger_findings),
        })

        # ── Phase 2.13: S3 Bucket Enumeration ────────────────────────────────
        # Checks public S3 buckets using company name variants derived from
        # the target domains. Public buckets = Critical/High on H1.
        await _push_event(redis, scan_id, "phase_start", {"phase": "s3_enum"})
        await _push_event(redis, scan_id, "tool_start", {
            "tool": "s3_enum",
            "detail": f"{len(scope.in_scope_domains)} domains → bucket variants",
        })
        s3_out = os.path.join(scan_dir, "s3_buckets.jsonl")
        s3_findings = await tool_runner.run_s3_enum(scope.in_scope_domains, s3_out)
        await _push_event(redis, scan_id, "tool_done", {
            "tool": "s3_enum", "count": len(s3_findings),
        })
        await _push_event(redis, scan_id, "phase_done", {
            "phase": "s3_enum", "public_buckets": len(s3_findings),
        })

        # ── Phase 3: Nuclei scan ──────────────────────────────────────────────
        # Smart URL selection: nuclei works best on a focused set of high-value targets.
        # Too many URLs (3000+) makes scans take hours; cap at 500 prioritised URLs.
        # Skipped if program notes say "no automated scanners" / "manual testing only".
        raw_findings: list[dict] = []
        await _push_event(redis, scan_id, "phase_start", {"phase": "nuclei_scan"})

        if do_nuclei:
            nuclei_urls = _select_nuclei_targets(all_target_urls, live_urls, max_urls=500)
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
                raw_findings = await tool_runner.run_nuclei(
                    nuclei_urls, nuclei_out, scope, detected_techs=detected_techs
                )
            finally:
                ticker.cancel()

            await _push_event(redis, scan_id, "phase_done", {
                "phase": "nuclei_scan",
                "raw_findings": len(raw_findings),
            })
        else:
            await _push_event(redis, scan_id, "phase_done", {
                "phase": "nuclei_scan",
                "skipped": True,
                "reason": "program prohibits automated scanners",
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

        # Convert email security findings → Finding objects
        for email_issue in email_findings:
            domain = email_issue["domain"]
            checks = email_issue["checks_failed"]
            # matched-at = target domain URL so L1 scope filter passes
            target_url = f"https://{domain}"
            issues_text = "; ".join(
                f"{i['check']}: {i['detail']}" for i in email_issue.get("issues", [])
            )
            raw_findings.append({
                "_source": "email_security",
                "info": {
                    "name": f"Email Security Misconfiguration — {checks} ({domain})",
                    "severity": email_issue["severity"],
                    "tags": ["misconfig", "email-security", "spf", "dmarc"],
                    "description": (
                        f"Email security issues detected for {domain}: {issues_text}. "
                        f"Impact: {email_issue['impact']}"
                    ),
                },
                "matched-at": target_url,
                "type": "email-misconfig",
                "_domain": domain,
                "_checks_failed": checks,
                "_issues": email_issue.get("issues", []),
            })

        # Convert Swagger/OpenAPI spec findings → Finding objects
        for _sw in swagger_findings:
            raw_findings.append({
                "_source": "swagger_discovery",
                "info": {
                    "name": f"Exposed API Specification — {_sw['spec_url']}",
                    "severity": _sw["severity"],
                    "tags": ["exposure", "api-docs", "information-disclosure"],
                    "description": _sw["impact"],
                },
                "matched-at": _sw["spec_url"],
                "type": "exposure",
                "_endpoints_count": _sw["endpoints_count"],
                "_sample_paths": _sw.get("sample_paths", []),
            })

        # Convert S3 bucket enum findings → Finding objects
        for _s3 in s3_findings:
            raw_findings.append({
                "_source": "s3_enum",
                "info": {
                    "name": f"Public S3 Bucket — {_s3['bucket']}",
                    "severity": _s3["severity"],
                    "tags": ["exposure", "s3", "misconfig", "cloud"],
                    "description": _s3["impact"],
                },
                "matched-at": _s3["url"],
                "type": "exposure",
                "_bucket": _s3["bucket"],
                "_publicly_listed": _s3["publicly_listed"],
            })

        # Convert dalfox XSS findings → Finding objects
        for _xss in dalfox_findings:
            raw_findings.append({
                "_source": "dalfox",
                "info": {
                    "name": f"Cross-Site Scripting (XSS) — {_xss.get('param', 'unknown param')}",
                    "severity": "high",
                    "tags": ["xss", "injection"],
                    "description": str(_xss.get("evidence", _xss)),
                },
                "matched-at": _xss.get("url", ""),
                "type": "xss",
                "_param": _xss.get("param", ""),
                "_evidence": str(_xss.get("evidence", ""))[:500],
            })

        # Convert credential-in-URL findings → Finding objects
        for cred in cred_urls:
            if is_in_scope(cred["url"], scope):
                _source_label = (
                    "URL userinfo (RFC-3986 user:password@host format)"
                    if cred["source"] == "userinfo"
                    else "URL path (credentials embedded in path segment)"
                )
                _user_info = f"user: {cred['username']}" if cred["username"] else "pattern matched in URL path"
                raw_findings.append({
                    "_source": "gau_credentials",
                    "info": {
                        "name": f"Credentials Exposed in URL — {cred['host']}",
                        "severity": "high",
                        "tags": ["exposure", "credentials", "sensitive-data"],
                        "description": (
                            f"GAU found a URL with plaintext credentials ({_user_info}) "
                            f"via {_source_label} for {cred['host']}. "
                            f"Credentials in URLs are logged by proxies, browsers, CDNs, "
                            f"and web server access logs, leading to credential exposure. "
                            f"Evidence URL: {cred['url']}"
                        ),
                    },
                    "matched-at": f"https://{cred['host']}",
                    "type": "exposure",
                    "_credential_url": cred["url"],
                    "_username": cred["username"] or "[extracted from path]",
                    "_password": "[REDACTED]",
                })

        # Convert GitHub dork findings → Finding objects
        for gh in github_findings:
            # matched-at must be the TARGET domain URL (not GitHub URL) so the
            # L1 scope filter passes. The GitHub evidence URL is kept in _evidence_url.
            query = gh.get("query", "")
            is_org_repo = gh.get("_is_org_repo", False)
            target_domain = next(
                (d.lstrip("*.") for d in scope.in_scope_domains if d.lstrip("*.") in query),
                scope.in_scope_domains[0].lstrip("*.") if scope.in_scope_domains else "",
            )
            target_url = f"https://{target_domain}" if target_domain else gh["html_url"]

            # Org-repo findings get higher severity — company's own committed secrets
            severity = gh["severity"]
            if is_org_repo and gh["severity"] in ("medium", "low"):
                severity = "high"

            raw_findings.append({
                "_source": "github_dork",
                "info": {
                    "name": f"Exposed {gh['secret_type']} in {'Official' if is_org_repo else 'Third-Party'} GitHub Repository",
                    "severity": severity,
                    "tags": ["token-disclosure", "exposure", "github"]
                          + (["official-repo"] if is_org_repo else ["third-party"]),
                    "description": (
                        f"Secret '{gh['secret_type']}' for {target_domain} found publicly "
                        f"in {'OFFICIAL org repo' if is_org_repo else 'third-party repo'} "
                        f"{gh['repo']} → {gh['file_path']}. "
                        f"{'This is a COMPANY-OWNED repository — much higher impact.' if is_org_repo else ''}"
                        f"Search query: {query}"
                    ),
                },
                "matched-at": target_url,   # scope-passable target URL
                "type": "token-disclosure",
                "_repo": gh["repo"],
                "_file_path": gh["file_path"],
                "_evidence_url": gh["html_url"],  # actual GitHub URL for the report
                "_snippet": gh["snippet"],
                "_secret_type": gh["secret_type"],
            })

        # ── Phase 4.5: SQLi validation with sqlmap ───────────────────────────
        # Find any SQLi candidates from nuclei and run sqlmap in safe time-based mode.
        # Max 3 candidates — each sqlmap run can take up to 5 min.
        sqli_candidates: list[str] = []
        for _raw in raw_findings:
            _tags = str(_raw.get("info", {}).get("tags", [])).lower()
            _name = _raw.get("info", {}).get("name", "").lower()
            if "sqli" in _tags or "sql" in _name:
                _url = _raw.get("matched-at", "")
                if _url and is_in_scope(_url, scope) and _url not in sqli_candidates:
                    sqli_candidates.append(_url)

        if sqli_candidates:
            await _push_event(redis, scan_id, "phase_start", {"phase": "sqli_validation"})
            sqlmap_confirmed: list[dict] = []

            for _sql_url in sqli_candidates[:3]:
                await _push_event(redis, scan_id, "tool_start", {
                    "tool": "sqlmap",
                    "detail": _sql_url[:120],
                })
                try:
                    _sql_results = await tool_runner.run_sqlmap(_sql_url, scan_dir)
                    sqlmap_confirmed.extend(_sql_results)
                    await _push_event(redis, scan_id, "tool_done", {
                        "tool": "sqlmap", "count": len(_sql_results),
                    })
                except Exception as _sm_err:
                    # sqlmap not installed yet (requires rebuild) — skip silently
                    await _push_event(redis, scan_id, "tool_done", {
                        "tool": "sqlmap", "count": 0,
                        "note": f"sqlmap unavailable: {str(_sm_err)[:80]}",
                    })

            # Promote sqlmap-confirmed SQLi as high-priority raw findings
            for _sf in sqlmap_confirmed:
                raw_findings.append({
                    "_source": "sqlmap",
                    "info": {
                        "name": "SQL Injection (Time-Based Blind) — Confirmed by sqlmap",
                        "severity": "high",
                        "tags": ["sqli", "injection"],
                        "description": _sf["evidence"][:500],
                    },
                    "matched-at": _sf["url"],
                    "type": "sqli",
                })

            await _push_event(redis, scan_id, "phase_done", {
                "phase": "sqli_validation",
                "candidates": len(sqli_candidates),
                "confirmed": len(sqlmap_confirmed),
            })

        for raw in raw_findings:
            # Wrap each finding individually so one Claude failure / network blip
            # doesn't abort the remaining findings and crash the entire scan.
            try:
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

                    # Capture HTTP evidence for JS/secret findings (validates key is live)
                    try:
                        _raw_ev = json.loads(finding.raw_output)
                        _ev_src = _raw_ev.get("_source", "")
                        if _ev_src in ("js_scanner",):
                            _ev_out = os.path.join(scan_dir, f"evidence_{finding.id}.json")
                            _ev_data = await tool_runner.capture_finding_evidence(_raw_ev, _ev_out)
                            finding.http_evidence = json.dumps(_ev_data)
                            await _push_event(redis, scan_id, "evidence_captured", {
                                "finding_id": finding.id,
                                "source": _ev_src,
                                "key_validated": (
                                    _ev_data.get("key_validation", {}) or {}
                                ).get("validated", False),
                            })
                    except Exception:
                        pass

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
                    except Exception as _rep_err:
                        await _push_event(redis, scan_id, "report_error", {
                            "finding_id": finding.id,
                            "error": str(_rep_err),
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

            except Exception as _finding_err:
                # Single finding failed (Claude timeout, network error, bad JSON) —
                # log and continue with the rest.
                rejected_count += 1
                await _push_event(redis, scan_id, "finding_error", {
                    "error": str(_finding_err),
                    "raw_title": str(raw.get("info", {}).get("name", ""))[:120],
                })

        # Save scan state for delta comparison on next scan
        try:
            _delta_data = {
                "scan_id": scan_id,
                "scan_date": datetime.utcnow().isoformat(),
                "subdomains": sorted(all_subdomains),
                "live_urls": sorted(live_urls),
            }
            async with aiofiles.open(_delta_file, "w", encoding="utf-8") as _df:
                await _df.write(json.dumps(_delta_data, indent=2))
        except Exception:
            pass

        job.findings_count = approved_count
        job.status = ScanStatus.done
        job.finished_at = datetime.utcnow()
        await _save_job(job, program_id)

        await _push_event(redis, scan_id, "scan_done", {
            "approved": approved_count,
            "rejected": rejected_count,
            "reports": job.reports_count,
        })

        # Expire scan event list after 24 h so Redis doesn't accumulate indefinitely
        if redis:
            await redis.expire(f"scan:{scan_id}:events", 86400)

    except Exception as e:
        import logging
        logging.getLogger("scans").exception("Scan %s crashed: %s", scan_id, e)
        job.status = ScanStatus.failed
        job.finished_at = datetime.utcnow()
        await _save_job(job, program_id)
        await _push_event(redis, scan_id, "scan_error", {"error": str(e)})
        # Expire failed scan events after 24 h
        if redis:
            await redis.expire(f"scan:{scan_id}:events", 86400)
        # Do NOT re-raise — re-raising a fire-and-forget asyncio.create_task produces
        # noisy "Task exception was never retrieved" logs with no benefit.
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
async def stream_scan(program_id: str, scan_id: str, request: Request):
    """
    SSE stream of live scan output.
    Reads events from Redis list for this scan_id.
    Uses SSE event IDs so browser reconnects resume from the last received event
    instead of replaying everything from position 0.
    Detects zombie scans (interrupted mid-run) and emits scan_error rather than
    waiting 2 hours for events that will never arrive.
    """
    async def event_generator():
        redis = await _get_redis()
        # Resume from Last-Event-ID if the browser is reconnecting
        _last_id = request.headers.get("last-event-id", "")
        cursor = (int(_last_id) + 1) if _last_id.isdigit() else 0
        idle_ticks = 0
        last_event_type: str = ""

        while True:
            if redis:
                events = await redis.lrange(f"scan:{scan_id}:events", cursor, cursor + 49)
                if events:
                    idle_ticks = 0
                    for raw_event in events:
                        event_id = cursor   # capture before increment
                        cursor += 1
                        parsed = json.loads(raw_event)
                        last_event_type = parsed["type"]
                        yield {"event": last_event_type, "data": json.dumps(parsed["data"]), "id": str(event_id)}

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
