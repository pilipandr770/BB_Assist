from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.models import ApiResponse
from backend.services import program_scorer

router = APIRouter()


class AnalyzeProgramsRequest(BaseModel):
    programs: list[str]


@router.post("/analyze", response_model=ApiResponse)
async def analyze_programs(body: AnalyzeProgramsRequest):
    programs = [p.strip() for p in (body.programs or []) if p and p.strip()]
    if len(programs) < 1:
        raise HTTPException(status_code=400, detail="Provide at least one program scope text")
    if len(programs) > 20:
        raise HTTPException(status_code=400, detail="Max 20 programs per request")

    scored = await program_scorer.score_multiple(programs)
    return ApiResponse(success=True, data={"results": scored})
