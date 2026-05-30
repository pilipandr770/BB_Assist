"""
HackerOne program discovery endpoints.

GET  /api/discover/status               — H1 + Telegram connection status
GET  /api/discover/programs             — list matching H1 programs
POST /api/discover/import/{handle}      — import program (scope parse only)
POST /api/discover/import-scan/{handle} — import + generate plan + start scan
"""
import asyncio
import json
import logging
import os
import re
import uuid
from datetime import datetime

import aiofiles
import httpx
from fastapi import APIRouter, HTTPException, Query

from backend import database
from backend.config import settings
from backend.models import Program, ScanCreate
from backend.services import h1_discovery, scope_parser, claude_service

log = logging.getLogger("discover")
router = APIRouter()

WORKSPACE = settings.workspace_dir


# ── status ───────────────────────────────────────────────────────────────────

@router.get("/status")
async def integration_status():
    """
    Returns live connection status for H1 API and Telegram bot.
    Makes one lightweight API call each to verify credentials are valid.
    """
    h1_ok = bool(settings.h1_username and settings.h1_api_token)
    tg_ok = bool(settings.telegram_bot_token and settings.telegram_chat_id)

    result = {
        "h1": {
            "configured": h1_ok,
            "username": settings.h1_username or "",
        },
        "telegram": {
            "configured": tg_ok,
            "bot_username": None,
            "bot_name": None,
        },
    }

    if tg_ok:
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                r = await c.get(
                    f"https://api.telegram.org/bot{settings.telegram_bot_token}/getMe"
                )
                if r.status_code == 200:
                    bot = r.json().get("result", {})
                    result["telegram"]["bot_username"] = bot.get("username")
                    result["telegram"]["bot_name"] = bot.get("first_name")
        except Exception:
            pass

    return result


# ── helpers ──────────────────────────────────────────────────────────────────

def _slugify(name: str) -> str:
    slug = name.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_-]+", "-", slug)
    return slug[:60]


def _program_dir(slug: str) -> str:
    return os.path.join(WORKSPACE, slug)


def _program_file(slug: str) -> str:
    return os.path.join(_program_dir(slug), "program.json")


def _plan_file(slug: str) -> str:
    return os.path.join(_program_dir(slug), "plan.md")


async def _save_json(path: str, content: str) -> None:
    """Atomic write."""
    tmp = path + f".{uuid.uuid4().hex}.tmp"
    async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
        await f.write(content)
    os.replace(tmp, path)


async def _do_import(handle: str, name: str) -> tuple[str, "Program"]:
    """
    Fetch H1 policy text + structured scopes, build program text,
    parse with Claude, persist to disk. Returns (slug, program).
    """
    # Fetch policy text and scopes in parallel
    try:
        policy_text, (in_scope, out_of_scope) = await asyncio.gather(
            h1_discovery.get_policy_text(handle),
            h1_discovery.get_program_scopes(handle),
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    except Exception as exc:
        log.error("H1 fetch error for %s: %s", handle, exc)
        raise HTTPException(status_code=502, detail=f"Failed to fetch data from H1: {exc}")

    if not policy_text and not in_scope:
        raise HTTPException(status_code=422, detail="Program has no scope data on HackerOne")

    program_name = name or handle
    raw_text = h1_discovery.build_program_text(handle, program_name, policy_text, in_scope, out_of_scope)

    try:
        scope = await scope_parser.get_scope(raw_text)
    except Exception as exc:
        log.error("Scope parse error for %s: %s", handle, exc)
        raise HTTPException(status_code=500, detail=f"Scope parsing failed: {exc}")

    slug = _slugify(program_name)
    program = Program(
        id=slug,
        name=program_name,
        slug=slug,
        raw_text=raw_text,
        scope=scope,
        created_at=datetime.utcnow(),
    )

    os.makedirs(_program_dir(slug), exist_ok=True)
    await _save_json(_program_file(slug), program.model_dump_json(indent=2))
    await database.save_program(program.id, program.name, program.raw_text)

    return slug, program


# ── routes ───────────────────────────────────────────────────────────────────

@router.get("/programs")
async def discover_programs(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=100),
):
    """
    List open H1 bounty programs.
    Requires H1_USERNAME + H1_API_TOKEN in .env.
    """
    if not h1_discovery.has_credentials():
        raise HTTPException(
            status_code=400,
            detail=(
                "H1_USERNAME and H1_API_TOKEN must be set in .env — "
                "generate a token at https://hackerone.com/settings/api_token/edit"
            ),
        )
    try:
        programs = await h1_discovery.list_programs(page=page, size=size)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    except Exception as exc:
        log.error("H1 API error: %s", exc)
        raise HTTPException(status_code=502, detail=f"HackerOne API error: {exc}")

    return {"programs": programs, "count": len(programs)}


@router.post("/import/{handle}")
async def import_program(handle: str, name: str = Query("")):
    """Fetch H1 scope and import program. Returns program_id."""
    if not h1_discovery.has_credentials():
        raise HTTPException(status_code=400, detail="H1_USERNAME and H1_API_TOKEN must be set in .env")

    slug, program = await _do_import(handle, name)
    return {"program_id": slug, "handle": handle}


@router.post("/import-scan/{handle}")
async def import_and_scan(handle: str, name: str = Query("")):
    """
    Import program from H1, generate a testing plan via Claude,
    then start a scan immediately.

    Telegram notifications fire automatically when:
      - a critical/high finding is confirmed
      - the scan completes
    Returns {program_id, scan_id, handle}.
    """
    if not h1_discovery.has_credentials():
        raise HTTPException(status_code=400, detail="H1_USERNAME and H1_API_TOKEN must be set in .env")

    # 1. Import program
    slug, program = await _do_import(handle, name)

    # 2. Generate plan via Claude
    try:
        plan_md = await claude_service.generate_plan(program.scope, program.raw_text)
    except Exception as exc:
        log.error("Plan generation error for %s: %s", slug, exc)
        raise HTTPException(status_code=500, detail=f"Plan generation failed: {exc}")

    await _save_json(_plan_file(slug), plan_md)

    # Persist plan into program record
    program.plan = plan_md
    await _save_json(_program_file(slug), program.model_dump_json(indent=2))

    # 3. Start scan — import here to avoid module-level circular import
    from backend.routers.scans import start_scan

    try:
        scan_result = await start_scan(
            ScanCreate(program_id=slug, approved_plan=plan_md)
        )
        scan_id: str = scan_result.data["id"]  # type: ignore[index]
    except HTTPException as exc:
        # Scope not scannable (no real domains, only platform domains, etc.)
        # Import already succeeded — return program_id without scan_id so the
        # frontend shows "Open Plan" instead of crashing.
        log.warning("Scan skipped for %s: %s", slug, exc.detail)
        return {"program_id": slug, "scan_id": None, "handle": handle, "scan_skip_reason": exc.detail}

    return {"program_id": slug, "scan_id": scan_id, "handle": handle}
