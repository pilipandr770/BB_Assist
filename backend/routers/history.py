from fastapi import APIRouter, HTTPException

from backend import database
from backend.models import ApiResponse

router = APIRouter()


@router.get("/programs", response_model=ApiResponse)
async def list_program_history():
    rows = await database.get_program_history()
    return ApiResponse(success=True, data={"programs": rows})


@router.get("/programs/{program_id}", response_model=ApiResponse)
async def get_program_history_detail(program_id: str):
    data = await database.get_program_detail(program_id)
    if not data:
        raise HTTPException(status_code=404, detail="Program not found in history")
    return ApiResponse(success=True, data=data)


@router.get("/scans/{scan_id}", response_model=ApiResponse)
async def get_scan_history(scan_id: str):
    data = await database.get_scan_findings(scan_id)
    if not data.get("scan"):
        raise HTTPException(status_code=404, detail="Scan not found")
    return ApiResponse(success=True, data=data)


@router.delete("/scans/{scan_id}", response_model=ApiResponse)
async def delete_scan_history(scan_id: str):
    await database.delete_scan(scan_id)
    return ApiResponse(success=True, data={"deleted": scan_id})
