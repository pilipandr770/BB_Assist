import json
import os
import re
import uuid
from datetime import datetime

import aiofiles
from fastapi import APIRouter, HTTPException

from backend.config import settings
from backend.models import ApiResponse, Program, ProgramCreate
from backend.services import claude_service, scope_parser

router = APIRouter()

WORKSPACE = settings.workspace_dir


def _slugify(name: str) -> str:
    """Convert program name to filesystem-safe slug."""
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


async def _load_program(program_id: str) -> Program:
    """Load program by ID (slug). Raises 404 if not found."""
    path = _program_file(program_id)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"Program '{program_id}' not found")
    async with aiofiles.open(path, encoding="utf-8") as f:
        data = json.loads(await f.read())
    return Program(**data)


async def _save_program(program: Program) -> None:
    """Persist program to workspace using atomic write (write-then-rename)."""
    try:
        os.makedirs(_program_dir(program.slug), exist_ok=True)
    except OSError as e:
        # errno 5 = Input/output error — Docker Desktop WSL2 volume IO issue.
        # Tell the user to restart Docker rather than showing a cryptic 500.
        raise HTTPException(
            status_code=503,
            detail=(
                f"Workspace volume IO error (errno {e.errno}). "
                "This is a Docker Desktop / WSL2 issue — restart Docker Desktop and try again."
            ),
        ) from e

    final = _program_file(program.slug)
    # Unique tmp per call — prevents collisions from concurrent saves
    tmp = final + f".{uuid.uuid4().hex}.tmp"
    try:
        async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
            await f.write(program.model_dump_json(indent=2))
        os.replace(tmp, final)  # atomic on Linux — no partial reads possible
    except OSError as e:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Workspace write error (errno {e.errno}). "
                "Restart Docker Desktop and try again."
            ),
        ) from e


@router.post("", response_model=ApiResponse)
async def create_program(body: ProgramCreate):
    """
    Save a new H1 program and parse its scope with Claude.
    Returns the program with parsed scope ready for plan generation.
    """
    slug = _slugify(body.name)

    # Parse scope via Claude
    scope = await scope_parser.get_scope(body.raw_text)

    program = Program(
        id=slug,
        name=body.name,
        slug=slug,
        raw_text=body.raw_text,
        scope=scope,
        created_at=datetime.utcnow(),
    )

    await _save_program(program)

    return ApiResponse(success=True, data=json.loads(program.model_dump_json()))


@router.get("", response_model=ApiResponse)
async def list_programs():
    """List all saved programs from workspace."""
    programs = []
    if not os.path.exists(WORKSPACE):
        return ApiResponse(success=True, data={"programs": []})

    for entry in os.scandir(WORKSPACE):
        if entry.is_dir():
            prog_file = os.path.join(entry.path, "program.json")
            if os.path.exists(prog_file):
                async with aiofiles.open(prog_file, encoding="utf-8") as f:
                    data = json.loads(await f.read())
                programs.append(data)

    # Sort by created_at descending
    programs.sort(key=lambda p: p.get("created_at", ""), reverse=True)
    return ApiResponse(success=True, data={"programs": programs})


@router.get("/{program_id}", response_model=ApiResponse)
async def get_program(program_id: str):
    """Load saved program by ID (slug)."""
    program = await _load_program(program_id)
    return ApiResponse(success=True, data=json.loads(program.model_dump_json()))


@router.post("/{program_id}/plan", response_model=ApiResponse)
async def generate_plan(program_id: str):
    """
    Generate testing plan for a program via Claude.
    Idempotent: if plan already exists on disk, returns it without re-calling Claude.
    """
    program = await _load_program(program_id)

    if not program.scope:
        raise HTTPException(status_code=400, detail="Program has no parsed scope. Re-create it.")

    plan_path = _plan_file(program.slug)

    # Idempotency guard — concurrent duplicate requests return the same plan
    if os.path.exists(plan_path) and program.plan:
        return ApiResponse(success=True, data={"plan": program.plan, "program_id": program_id})

    plan_markdown = await claude_service.generate_plan(program.scope, program.raw_text)

    # Atomic plan file write
    tmp_plan = plan_path + f".{uuid.uuid4().hex}.tmp"
    async with aiofiles.open(tmp_plan, "w", encoding="utf-8") as f:
        await f.write(plan_markdown)
    os.replace(tmp_plan, plan_path)

    # Update program record (atomic)
    program.plan = plan_markdown
    await _save_program(program)

    return ApiResponse(success=True, data={"plan": plan_markdown, "program_id": program_id})


@router.get("/{program_id}/plan", response_model=ApiResponse)
async def get_plan(program_id: str):
    """Load saved plan for a program."""
    plan_path = _plan_file(program_id)
    if not os.path.exists(plan_path):
        raise HTTPException(status_code=404, detail="No plan generated yet. POST /plan first.")

    async with aiofiles.open(plan_path, encoding="utf-8") as f:
        plan = await f.read()

    return ApiResponse(success=True, data={"plan": plan, "program_id": program_id})
