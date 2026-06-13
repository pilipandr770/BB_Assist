import json
import os

import aiofiles
from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from backend.config import settings
from backend.models import ApiResponse, Finding, Program, Scope
from backend.services import report_generator, h1_api_service, telegram_notifier

router = APIRouter()


class H1SubmitRequest(BaseModel):
    h1_program_handle: str = ""  # override stored handle if provided

WORKSPACE = settings.workspace_dir


async def _load_finding(program_id: str, finding_id: str) -> Finding:
    """Load a filtered finding by ID."""
    path = os.path.join(WORKSPACE, program_id, "findings", "filtered", f"{finding_id}.json")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    async with aiofiles.open(path, encoding="utf-8") as f:
        return Finding(**json.loads(await f.read()))


async def _load_program(program_id: str) -> Program:
    """Load full program from program.json."""
    prog_file = os.path.join(WORKSPACE, program_id, "program.json")
    if not os.path.exists(prog_file):
        raise HTTPException(status_code=404, detail=f"Program '{program_id}' not found")
    async with aiofiles.open(prog_file, encoding="utf-8") as f:
        return Program(**json.loads(await f.read()))


async def _load_scope(program_id: str) -> Scope:
    """Load scope from program.json."""
    program = await _load_program(program_id)
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


@router.get("/{program_id}/{report_id}/meta", response_model=ApiResponse)
async def get_report_meta(program_id: str, report_id: str):
    """Return report metadata (.json) including quality gate info."""
    meta_path = os.path.join(WORKSPACE, program_id, "reports", f"{report_id}.json")
    if not os.path.exists(meta_path):
        raise HTTPException(status_code=404, detail=f"Report metadata '{report_id}' not found")

    async with aiofiles.open(meta_path, encoding="utf-8") as f:
        return ApiResponse(success=True, data=json.loads(await f.read()))


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


@router.post("/{program_id}/{report_id}/submit", response_model=ApiResponse)
async def submit_report_to_h1(program_id: str, report_id: str, body: H1SubmitRequest):
    """
    Submit an approved report to HackerOne via H1 REST API.
    Requires H1_USERNAME and H1_API_TOKEN set in environment.
    Returns {success, h1_report_id, h1_report_url} or error.
    """
    if not settings.h1_username or not settings.h1_api_token:
        raise HTTPException(
            status_code=400,
            detail="H1_USERNAME and H1_API_TOKEN must be configured to use auto-submit",
        )

    # Load report markdown
    report_path = os.path.join(WORKSPACE, program_id, "reports", f"{report_id}.md")
    meta_path = os.path.join(WORKSPACE, program_id, "reports", f"{report_id}.json")
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found")

    async with aiofiles.open(report_path, encoding="utf-8") as f:
        markdown = await f.read()

    meta = {}
    if os.path.exists(meta_path):
        async with aiofiles.open(meta_path, encoding="utf-8") as f:
            meta = json.loads(await f.read())

    # Resolve program handle: request body > stored program h1_handle > program slug
    program = await _load_program(program_id)
    handle = (
        body.h1_program_handle
        or program.h1_program_handle
        or program.slug
    )
    if not handle:
        raise HTTPException(status_code=400, detail="No HackerOne program handle configured")

    title = meta.get("title", f"Report {report_id[:8]}")
    severity = meta.get("severity", "medium")
    vuln_type = meta.get("vuln_type", "")

    result = await h1_api_service.submit_report(
        report_markdown=markdown,
        report_title=title,
        severity=severity,
        program_handle=handle,
        vuln_type=vuln_type,
        h1_username=settings.h1_username,
        h1_api_token=settings.h1_api_token,
    )

    if result.get("success"):
        # Persist h1 submission info to meta
        meta["h1_submitted"] = True
        meta["h1_report_id"] = result["h1_report_id"]
        meta["h1_report_url"] = result["h1_report_url"]
        async with aiofiles.open(meta_path, "w") as f:
            await f.write(json.dumps(meta, indent=2))

        # Telegram notification
        finding_id = meta.get("finding_id", "")
        await telegram_notifier.send_report_submitted(
            program_name=program.name,
            title=title,
            severity=severity,
            h1_report_url=result["h1_report_url"],
        )

    return ApiResponse(success=result.get("success", False), data=result)
