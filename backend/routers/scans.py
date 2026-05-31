import asyncio
import json
import os
import uuid
from datetime import datetime
from urllib.parse import urlparse

import aiofiles
import redis.asyncio as aioredis
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from backend import database
from backend.config import settings
from backend.models import ApiResponse, Finding, ScanCreate, ScanJob, ScanStatus, Severity
# settings is used for: workspace_dir, github_token, redis_url
from backend.services import claude_service, passive_recon, report_generator, tool_runner
from backend.services.phases.delta_history_phase import load_delta_baseline, save_delta_history
from backend.services.phases.non_web_pipeline_phase import run_non_web_pipeline_phase
from backend.services.phases.persist_raw_findings_phase import persist_raw_findings_phase
from backend.services.phases.pipeline_mode_phase import resolve_pipeline_mode_config
from backend.services.phases.scan_finalize_phase import finalize_scan_failure, finalize_scan_success
from backend.services.phases.web_pipeline_phase import (
    run_web_pipeline,
    select_ffuf_targets as _select_ffuf_targets,
    select_nuclei_targets as _select_nuclei_targets,
)
from backend.services import telegram_notifier

router = APIRouter()

WORKSPACE = settings.workspace_dir
TAKEOVER_PHASE_TIMEOUT_S = 420


class RerunPhaseRequest(BaseModel):
    phase: str

_PLATFORM_SCOPE_DOMAINS = {
    "hackerone.com", "bugcrowd.com", "intigriti.com", "yeswehack.com", "huntr.com",
}


def _is_platform_scope_domain(domain: str) -> bool:
    d = domain.lower().strip().lstrip("*.")
    return any(d == base or d.endswith("." + base) for base in _PLATFORM_SCOPE_DOMAINS)


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


def _phase_file(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [x.strip() for x in f if x.strip()]


def _discover_program_id_by_scan(scan_id: str) -> str | None:
    if not os.path.exists(WORKSPACE):
        return None
    for entry in os.scandir(WORKSPACE):
        if not entry.is_dir():
            continue
        p = os.path.join(entry.path, "scans", scan_id, "job.json")
        if os.path.exists(p):
            return entry.name
    return None


async def _rerun_phase_pipeline(program_id: str, scan_id: str, phase: str) -> None:
    redis = await _get_redis()
    scan_dir = _scan_dir(program_id, scan_id)
    recon_dir = os.path.join(WORKSPACE, program_id, "recon")
    rerun_job = await _load_job(program_id, scan_id)

    try:
        await _push_event(redis, scan_id, "phase_start", {"phase": phase})

        httpx_path = os.path.join(recon_dir, "httpx.jsonl")
        all_urls_path = os.path.join(recon_dir, "all_urls.txt")
        subfinder_path = os.path.join(recon_dir, "subfinder.txt")
        nuclei_out = os.path.join(scan_dir, "nuclei_cve.jsonl")

        live_urls: list[str] = []
        if os.path.exists(httpx_path):
            try:
                import aiofiles as _af
                async with _af.open(httpx_path, encoding="utf-8") as _f:
                    async for _line in _f:
                        _line = _line.strip()
                        if not _line:
                            continue
                        try:
                            _d = json.loads(_line)
                            _u = _d.get("url")
                            if _u:
                                live_urls.append(_u)
                        except Exception:
                            continue
            except Exception:
                live_urls = []

        if phase == "passive_recon":
            program = await _load_scope_and_program(program_id)
            domains = [d.lstrip("*.") for d in (program.scope.in_scope_domains or []) if d]
            all_subs = set()
            all_urls = set()
            for domain in domains[:5]:
                subs, urls = await passive_recon.run_all_passive(domain)
                all_subs.update(subs)
                all_urls.update(urls)
            await _push_event(redis, scan_id, "tool_done", {
                "tool": "passive_recon_rerun",
                "subdomains": len(all_subs),
                "urls": len(all_urls),
            })

        elif phase == "nuclei":
            all_urls = _phase_file(all_urls_path)
            targets = _select_nuclei_targets(all_urls, live_urls, max_urls=500)
            await _push_event(redis, scan_id, "tool_start", {"tool": "nuclei_rerun", "detail": f"{len(targets)} targets"})
            findings = await tool_runner.run_nuclei(
                targets,
                nuclei_out,
                scope=(await _load_scope_and_program(program_id)).scope,
                session_cookies=rerun_job.session_cookies,
                auth_header=rerun_job.auth_header,
            )
            await _push_event(redis, scan_id, "tool_done", {"tool": "nuclei_rerun", "count": len(findings)})

        elif phase == "js_scan":
            all_urls = _phase_file(all_urls_path)
            js_urls = [u for u in all_urls if u.lower().endswith(".js")]
            js_out = os.path.join(scan_dir, "js_scan_rerun.jsonl")
            await _push_event(redis, scan_id, "tool_start", {"tool": "js_scan_rerun", "detail": f"{len(js_urls)} js files"})
            js_findings = await tool_runner.run_js_scanner(js_urls[:200], js_out)
            await _push_event(redis, scan_id, "tool_done", {"tool": "js_scan_rerun", "count": len(js_findings)})

        elif phase == "ffuf":
            ffuf_targets = _select_ffuf_targets(live_urls, max_hosts=5)
            total = 0
            for i, host_url in enumerate(ffuf_targets, 1):
                ffuf_out = os.path.join(scan_dir, f"ffuf_rerun_{i}.jsonl")
                await _push_event(redis, scan_id, "tool_start", {"tool": "ffuf_rerun", "detail": host_url})
                results = await tool_runner.run_ffuf(
                    host_url,
                    "",
                    ffuf_out,
                    session_cookies=rerun_job.session_cookies,
                    auth_header=rerun_job.auth_header,
                )
                total += len(results)
            await _push_event(redis, scan_id, "tool_done", {"tool": "ffuf_rerun", "count": total})

        elif phase == "cors":
            cors_out = os.path.join(scan_dir, "cors_rerun.jsonl")
            findings = await tool_runner.run_cors_checker(live_urls[:60], cors_out)
            await _push_event(redis, scan_id, "tool_done", {"tool": "cors_rerun", "count": len(findings)})

        elif phase == "takeover":
            subs = _phase_file(subfinder_path)
            takeover_out = os.path.join(scan_dir, "takeover_rerun.jsonl")
            try:
                findings = await asyncio.wait_for(
                    tool_runner.run_subdomain_takeover(subs[:200], takeover_out),
                    timeout=TAKEOVER_PHASE_TIMEOUT_S,
                )
                await _push_event(redis, scan_id, "tool_done", {"tool": "takeover_rerun", "count": len(findings)})
            except asyncio.TimeoutError:
                await _push_event(redis, scan_id, "tool_error", {
                    "tool": "takeover_rerun",
                    "error": f"timeout after {TAKEOVER_PHASE_TIMEOUT_S}s",
                })
                await _push_event(redis, scan_id, "phase_done", {
                    "phase": phase,
                    "rerun": True,
                    "timeout": True,
                })
                return

        elif phase == "sqli":
            candidates = []
            if os.path.exists(nuclei_out):
                import aiofiles as _af
                async with _af.open(nuclei_out, encoding="utf-8") as _f:
                    async for _line in _f:
                        _line = _line.strip()
                        if not _line:
                            continue
                        try:
                            _d = json.loads(_line)
                        except Exception:
                            continue
                        tags = ",".join((_d.get("info", {}) or {}).get("tags", [])).lower()
                        tid = str(_d.get("template-id", "")).lower()
                        if "sqli" in tags or "sql" in tid:
                            _url = _d.get("matched-at") or _d.get("host")
                            if _url:
                                candidates.append(_url)
            confirmed = 0
            for url in list(dict.fromkeys(candidates))[:5]:
                res = await tool_runner.run_sqlmap(url, scan_dir)
                confirmed += len(res)
            await _push_event(redis, scan_id, "tool_done", {
                "tool": "sqli_rerun",
                "count": confirmed,
                "candidates": len(candidates),
            })
        else:
            raise ValueError(f"Unknown phase: {phase}")

        await _push_event(redis, scan_id, "phase_done", {"phase": phase, "rerun": True})

        job = await _load_job(program_id, scan_id)
        await _push_event(redis, scan_id, "scan_done", {
            "approved": job.findings_count,
            "rejected": 0,
            "reports": job.reports_count,
        })

    except Exception as e:
        await _push_event(redis, scan_id, "scan_error", {"error": f"rerun failed: {e}"})
    finally:
        if redis:
            await redis.aclose()


# ── scan orchestration ────────────────────────────────────────────────────────

async def _run_scan_pipeline(job: ScanJob) -> None:
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
    llm_usage_start = claude_service.get_usage_snapshot()

    try:
        # Update job status
        job.status = ScanStatus.running
        job.started_at = datetime.utcnow()
        await _save_job(job, program_id)
        await database.update_scan_status(
            job.id,
            status=ScanStatus.running.value,
            started_at=job.started_at.isoformat() if job.started_at else None,
        )

        # ── Delta scanning: load baseline from previous scan ─────────────────
        # Comparing current scan against the previous one lets us highlight NEW
        # subdomains / endpoints that appeared since last run — first-mover advantage.
        delta_file = os.path.join(WORKSPACE, program_id, "scan_history.json")

        async def _emit_delta(event_type: str, data: dict) -> None:
            await _push_event(redis, scan_id, event_type, data)

        delta_baseline = await load_delta_baseline(
            delta_file=delta_file,
            emit=_emit_delta,
        )
        prev_subdomains: set[str] = delta_baseline["prev_subdomains"]
        prev_live_urls: set[str] = delta_baseline["prev_live_urls"]

        program = await _load_scope_and_program(program_id)
        scope = program.scope

        mode_config = await resolve_pipeline_mode_config(
            job=job,
            scope=scope,
            program_id=program_id,
            save_job=_save_job,
        )
        _scan_mode = mode_config["scan_mode"]
        prog_type = mode_config["prog_type"]
        do_katana = mode_config["do_katana"]
        do_ffuf = mode_config["do_ffuf"]
        do_arjun = mode_config["do_arjun"]
        arjun_max = mode_config["arjun_max"]
        do_nuclei = mode_config["do_nuclei"]
        blocked_markers = mode_config["blocked_markers"]

        async def _emit_non_web(event_type: str, data: dict) -> None:
            await _push_event(redis, scan_id, event_type, data)

        non_web_completed = await run_non_web_pipeline_phase(
            scan_mode=_scan_mode,
            job=job,
            scope=scope,
            scan_id=scan_id,
            program_id=program_id,
            redis=redis,
            scan_dir=scan_dir,
            finding_dir=finding_dir,
            llm_usage_start=llm_usage_start,
            emit=_emit_non_web,
            persist_raw_findings=_persist_raw_findings,
        )
        if non_web_completed:
            return
        # Fall through to regular web pipeline if scan_mode == "api" but no spec URL

        async def _emit_web(event_type: str, data: dict) -> None:
            await _push_event(redis, scan_id, event_type, data)

        web_result = await run_web_pipeline(
            job=job,
            program=program,
            scope=scope,
            scan_id=scan_id,
            program_id=program_id,
            scan_dir=scan_dir,
            finding_dir=finding_dir,
            workspace_dir=WORKSPACE,
            do_katana=do_katana,
            do_ffuf=do_ffuf,
            do_arjun=do_arjun,
            arjun_max=arjun_max,
            do_nuclei=do_nuclei,
            blocked_markers=blocked_markers,
            prev_subdomains=prev_subdomains,
            prev_live_urls=prev_live_urls,
            github_token=settings.github_token,
            takeover_timeout_s=TAKEOVER_PHASE_TIMEOUT_S,
            emit=_emit_web,
        )

        await save_delta_history(
            delta_file=delta_file,
            scan_id=scan_id,
            all_subdomains=web_result["all_subdomains"],
            live_urls=web_result["live_urls"],
        )

        async def _emit_finalize(event_type: str, data: dict) -> None:
            await _push_event(redis, scan_id, event_type, data)

        await finalize_scan_success(
            job=job,
            program_id=program_id,
            program_name=program.name,
            scan_id=scan_id,
            approved_count=web_result["approved_count"],
            rejected_count=web_result["rejected_count"],
            llm_usage_start=llm_usage_start,
            save_job=_save_job,
            emit=_emit_finalize,
            redis=redis,
        )

    except Exception as e:
        import logging
        logging.getLogger("scans").exception("Scan %s crashed: %s", scan_id, e)
        async def _emit_finalize_error(event_type: str, data: dict) -> None:
            await _push_event(redis, scan_id, event_type, data)

        await finalize_scan_failure(
            job=job,
            program_id=program_id,
            scan_id=scan_id,
            error=e,
            llm_usage_start=llm_usage_start,
            save_job=_save_job,
            emit=_emit_finalize_error,
            redis=redis,
        )
        # Do NOT re-raise — re-raising a fire-and-forget asyncio.create_task produces
        # noisy "Task exception was never retrieved" logs with no benefit.
    finally:
        if redis:
            await redis.aclose()


async def _persist_raw_findings(
    redis,
    scan_id: str,
    program_id: str,
    raw_findings: list[dict],
    job: ScanJob,
    finding_dir: str,
    llm_usage_start: dict | None = None,
) -> None:
    async def _emit_persist(event_type: str, data: dict) -> None:
        await _push_event(redis, scan_id, event_type, data)

    await persist_raw_findings_phase(
        redis=redis,
        scan_id=scan_id,
        program_id=program_id,
        raw_findings=raw_findings,
        job=job,
        finding_dir=finding_dir,
        llm_usage_start=llm_usage_start,
        load_scope_and_program=_load_scope_and_program,
        save_job=_save_job,
        emit=_emit_persist,
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
    _effective_mode = (body.scan_mode or "auto").lower()
    _is_ip_mode = _effective_mode == "ip" or (program.scope and (program.scope.in_scope_cidrs or []))

    # Also consider scope.program_type + in_scope_urls for source_code detection
    _scope_prog_type = (program.scope.program_type or "web").lower() if program.scope else "web"
    _has_git_urls = any(
        "github.com" in u or "gitlab.com" in u or "bitbucket.org" in u
        for u in (program.scope.in_scope_urls or [])
    ) if program.scope else False
    _is_src_mode = (
        _effective_mode == "source_code"
        or bool(body.repo_url)
        or (_scope_prog_type == "source_code" and _has_git_urls)
    )

    # For IP/source_code modes domains are not required
    if not _is_ip_mode and not _is_src_mode:
        if not program.scope or not program.scope.in_scope_domains:
            raise HTTPException(
                status_code=400,
                detail="Scope has no in-scope domains. Claude could not extract targets from the program text. "
                       "Re-create the program with a complete HackerOne scope section that lists specific domains.",
            )

        in_scope_clean = [d.lstrip("*.").lower() for d in (program.scope.in_scope_domains or []) if d]
        if in_scope_clean and all(_is_platform_scope_domain(d) for d in in_scope_clean):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Parsed scope only contains bug bounty platform domains (e.g., bugcrowd/hackerone), "
                    "which indicates scope extraction fallback failed. Re-create the program using the full "
                    "live scope table and verify in-scope domains before starting a scan."
                ),
            )

    job = ScanJob(
        id=str(uuid.uuid4()),
        program_id=body.program_id,
        status=ScanStatus.pending,
        session_cookies=(body.session_cookies or "").strip(),
        auth_header=(body.auth_header or "").strip(),
        scan_mode=(body.scan_mode or "auto").strip(),
        api_spec_url=(body.api_spec_url or "").strip(),
        repo_url=(body.repo_url or "").strip(),
    )

    await _save_job(job, body.program_id)
    await database.save_scan(
        scan_id=job.id,
        program_id=job.program_id,
        status=job.status.value,
        started_at=job.started_at.isoformat() if job.started_at else None,
        finished_at=job.finished_at.isoformat() if job.finished_at else None,
        findings_count=job.findings_count,
        reports_count=job.reports_count,
        llm_cost_usd=job.llm_cost_usd,
    )

    # Launch scan as a free asyncio task (not a FastAPI BackgroundTask) so it
    # survives across uvicorn hot-reloads and doesn't block shutdown.
    asyncio.create_task(_run_scan_pipeline(job))

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
                        try:
                            terminal_job = await _load_job(program_id, scan_id)
                            if terminal_job.status not in (ScanStatus.done, ScanStatus.failed):
                                terminal_job.status = (
                                    ScanStatus.done if last_event_type == "scan_done" else ScanStatus.failed
                                )
                                terminal_job.finished_at = terminal_job.finished_at or datetime.utcnow()
                                await _save_job(terminal_job, program_id)
                                await database.update_scan_status(
                                    terminal_job.id,
                                    status=terminal_job.status.value,
                                    finished_at=terminal_job.finished_at.isoformat() if terminal_job.finished_at else None,
                                    findings_count=terminal_job.findings_count,
                                    reports_count=terminal_job.reports_count,
                                )
                        except Exception:
                            pass

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
                    if idle_ticks == 30:
                        try:
                            last_raw = await redis.lindex(f"scan:{scan_id}:events", -1)
                            if last_raw:
                                last_parsed = json.loads(last_raw)
                                last_type = last_parsed.get("type", "")

                                # If last stored event is terminal, close immediately
                                # even when client reconnected with cursor past the end.
                                if last_type in ("scan_done", "scan_error"):
                                    await redis.aclose()
                                    return

                                last_ts_str = last_parsed.get("ts", "")
                                if last_ts_str:
                                    from datetime import timezone
                                    last_ts = datetime.fromisoformat(last_ts_str)
                                    age_s = (datetime.now(timezone.utc) - last_ts.replace(tzinfo=timezone.utc)).total_seconds()
                                    # Long-running phases (e.g., nuclei/source scans) can be quiet for minutes.
                                    # Use a conservative threshold to avoid false-positive interruption errors.
                                    if age_s > 900:
                                        # Last event is >15 minutes old and nothing new → likely zombie
                                        try:
                                            stale_job = await _load_job(program_id, scan_id)
                                            if stale_job.status not in (ScanStatus.done, ScanStatus.failed):
                                                stale_job.status = ScanStatus.failed
                                                stale_job.finished_at = datetime.utcnow()
                                                await _save_job(stale_job, program_id)
                                                await database.update_scan_status(
                                                    stale_job.id,
                                                    status=ScanStatus.failed.value,
                                                    finished_at=stale_job.finished_at.isoformat() if stale_job.finished_at else None,
                                                    findings_count=stale_job.findings_count,
                                                    reports_count=stale_job.reports_count,
                                                )
                                        except Exception:
                                            pass

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


@router.post("/{scan_id}/rerun-phase", response_model=ApiResponse)
async def rerun_phase(scan_id: str, body: RerunPhaseRequest):
    allowed = {"nuclei", "js_scan", "ffuf", "passive_recon", "cors", "takeover", "sqli"}
    phase = (body.phase or "").strip().lower()
    if phase not in allowed:
        raise HTTPException(status_code=400, detail=f"Unsupported phase '{phase}'")

    program_id = _discover_program_id_by_scan(scan_id)
    if not program_id:
        raise HTTPException(status_code=404, detail="Scan not found")

    asyncio.create_task(_rerun_phase_pipeline(program_id, scan_id, phase))
    return ApiResponse(success=True, data={"scan_id": scan_id, "program_id": program_id, "phase": phase})


class ManualFindingCreate(BaseModel):
    program_id: str
    scan_id: str = ""          # optional — links to existing scan
    title: str
    url: str
    severity: str = "medium"
    vuln_type: str = "manual"
    description: str = ""
    steps_to_reproduce: str = ""


@router.post("/findings/manual", response_model=ApiResponse)
async def add_manual_finding(body: ManualFindingCreate):
    """
    Add a manually discovered finding (e.g. logic bug found during manual testing).
    Runs through the same AI filter and report generation as automated findings.
    """
    prog_file = os.path.join(WORKSPACE, body.program_id, "program.json")
    if not os.path.exists(prog_file):
        raise HTTPException(status_code=404, detail=f"Program '{body.program_id}' not found")

    program = await _load_scope_and_program(body.program_id)
    scope = program.scope

    try:
        sev = Severity(body.severity.lower())
    except ValueError:
        sev = Severity.medium

    raw_output = json.dumps({
        "title": body.title,
        "description": body.description,
        "steps_to_reproduce": body.steps_to_reproduce,
        "_source": "manual",
    })

    finding = Finding(
        id=str(uuid.uuid4()),
        scan_id=body.scan_id or "manual",
        program_id=body.program_id,
        tool="manual",
        title=body.title,
        url=body.url,
        severity=sev,
        vuln_type=body.vuln_type,
        raw_output=raw_output,
    )

    finding_dir = _finding_dir(body.program_id)
    os.makedirs(os.path.join(finding_dir, "filtered"), exist_ok=True)

    # Always approve manual findings (researcher already triaged)
    finding_path = os.path.join(finding_dir, "filtered", f"{finding.id}.json")
    async with aiofiles.open(finding_path, "w") as f:
        await f.write(finding.model_dump_json(indent=2))

    await database.save_finding(
        finding_id=finding.id,
        scan_id=finding.scan_id,
        title=finding.title,
        severity=finding.severity.value,
        vuln_type=finding.vuln_type,
        target=finding.url,
        passed_filter=1,
    )

    # Generate report
    report_data: dict = {}
    try:
        report = await report_generator.generate(finding, scope)
        async with aiofiles.open(finding_path, "w") as f:
            await f.write(finding.model_dump_json(indent=2))
        report_data = {"report_id": report.id, "title": report.title}
    except Exception as _rep_err:
        report_data = {"error": str(_rep_err)}

    if finding.severity in (Severity.critical, Severity.high):
        await telegram_notifier.send_critical_finding(
            program_name=program.name,
            title=finding.title,
            severity=finding.severity.value,
            target=finding.url,
        )

    return ApiResponse(success=True, data={
        "finding_id": finding.id,
        "severity": finding.severity.value,
        "report": report_data,
    })

