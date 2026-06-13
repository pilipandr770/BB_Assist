"""CT-log monitoring endpoint — check crt.sh for new subdomains."""

import json
import os

import aiofiles
from fastapi import APIRouter, HTTPException

from backend.config import settings
from backend.models import ApiResponse, Program
from backend.services import ct_monitor, telegram_notifier

router = APIRouter()

WORKSPACE = settings.workspace_dir


async def _load_program(program_id: str) -> Program:
    prog_file = os.path.join(WORKSPACE, program_id, "program.json")
    if not os.path.exists(prog_file):
        raise HTTPException(status_code=404, detail=f"Program '{program_id}' not found")
    async with aiofiles.open(prog_file, encoding="utf-8") as f:
        return Program(**json.loads(await f.read()))


@router.post("/{program_id}/check", response_model=ApiResponse)
async def check_ct_logs(program_id: str):
    """
    Query crt.sh for all subdomains, compare against previous snapshot,
    and return any new subdomains discovered since last check.
    Sends a Telegram notification if new subdomains are found.
    """
    program = await _load_program(program_id)
    if not program.scope or not program.scope.in_scope_domains:
        raise HTTPException(status_code=400, detail="Program has no in-scope domains")

    domains = [d.lstrip("*.") for d in program.scope.in_scope_domains]

    result = await ct_monitor.check_new_subdomains(
        program_id=program_id,
        domains=domains,
        workspace_dir=WORKSPACE,
    )

    if result["new_subdomains"]:
        await telegram_notifier.send_new_subdomains(
            program_name=program.name,
            new_subdomains=result["new_subdomains"],
        )

    return ApiResponse(success=True, data=result)


@router.get("/{program_id}/snapshot", response_model=ApiResponse)
async def get_ct_snapshot(program_id: str):
    """Return the last saved CT-log subdomain snapshot for a program."""
    snapshot_path = os.path.join(WORKSPACE, program_id, "ct_snapshot.json")
    if not os.path.exists(snapshot_path):
        return ApiResponse(success=True, data={"subdomains": [], "checked_at": None})

    async with aiofiles.open(snapshot_path, encoding="utf-8") as f:
        data = json.loads(await f.read())

    return ApiResponse(success=True, data=data)
