import json
import os

import aiofiles
from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from backend.config import settings
from backend.models import ApiResponse, Finding, Scope
from backend.services import report_generator

router = APIRouter()

WORKSPACE = settings.workspace_dir


async def _load_finding(program_id: str, finding_id: str) -> Finding:
    """Load a filtered finding by ID."""
    path = os.path.join(WORKSPACE, program_id, "findings", "filtered", f"{finding_id}.json")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    async with aiofiles.open(path, encoding="utf-8") as f:
        return Finding(**json.loads(await f.read()))


async def _load_scope(program_id: str) -> Scope:
    """Load scope from program.json."""
    prog_file = os.path.join(WORKSPACE, program_id, "program.json")
    if not os.path.exists(prog_file):
        raise HTTPException(status_code=404, detail=f"Program '{program_id}' not found")
    async with aiofiles.open(prog_file, encoding="utf-8") as f:
        prog_data = json.loads(await f.read())
    from backend.models import Program
    program = Program(**prog_data)
    if not program.scope:
        raise HTTPException(status_code=400, detail="Program has no scope")
    return program.scope


@router.post("/{program_id}/{finding_id}", response_model=ApiResponse)
async def generate_report(program_id: str, finding_id: str):
    """
    Generate H1-ready markdown report for a confirmed finding.
    Calls Claude, saves to workspace, returns report object.
    """
    finding = await _load_finding(program_id, finding_id)
    scope = await _load_scope(program_id)

    report = await report_generator.generate(finding, scope)

    return ApiResponse(success=True, data=json.loads(report.model_dump_json()))


@router.get("/{program_id}/{report_id}", response_class=PlainTextResponse)
async def get_report(program_id: str, report_id: str):
    """Return raw markdown report."""
    report_path = os.path.join(WORKSPACE, program_id, "reports", f"{report_id}.md")
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found")

    async with aiofiles.open(report_path, encoding="utf-8") as f:
        return await f.read()


@router.get("/{program_id}", response_model=ApiResponse)
async def list_reports(program_id: str):
    """List all generated reports for a program, with full metadata."""
    report_dir = os.path.join(WORKSPACE, program_id, "reports")
    if not os.path.exists(report_dir):
        return ApiResponse(success=True, data={"reports": []})

    reports = []
    for entry in os.scandir(report_dir):
        if entry.name.endswith(".json"):
            # Rich metadata file (saved alongside .md since v2)
            async with aiofiles.open(entry.path, encoding="utf-8") as f:
                try:
                    data = json.loads(await f.read())
                    reports.append(data)
                except Exception:
                    pass
        elif entry.name.endswith(".md"):
            # Fallback for legacy reports that have no .json yet
            report_id = entry.name.replace(".md", "")
            json_path = entry.path.replace(".md", ".json")
            if not os.path.exists(json_path):
                stat = entry.stat()
                reports.append({
                    "id": report_id,
                    "finding_id": None,
                    "title": f"Report {report_id[:8]}",
                    "severity": "medium",
                    "created_at": stat.st_ctime,
                })

    reports.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    return ApiResponse(success=True, data={"reports": reports})
