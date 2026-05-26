from pydantic import BaseModel
from typing import Optional
from enum import Enum
from datetime import datetime


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informative = "informative"


class ScanStatus(str, Enum):
    pending = "pending"
    running = "running"
    done = "done"
    failed = "failed"


# --- Scope ---

class Scope(BaseModel):
    in_scope_domains: list[str] = []
    in_scope_cidrs: list[str] = []        # IP ranges / CIDRs for network scanning
    in_scope_urls: list[str] = []
    out_of_scope_domains: list[str] = []
    excluded_vuln_types: list[str] = []
    allowed_test_endpoints: list[str] = []
    program_type: str = "web"  # web | api | ip | source_code | blockchain | mobile
    notes: str = ""


# --- Program ---

class ProgramCreate(BaseModel):
    name: str
    raw_text: str  # full copy-paste from HackerOne


class Program(BaseModel):
    id: str
    name: str
    slug: str
    raw_text: str
    scope: Optional[Scope] = None
    plan: Optional[str] = None  # markdown plan from Claude
    created_at: datetime = datetime.utcnow()


# --- Scan ---

class ScanCreate(BaseModel):
    program_id: str
    approved_plan: str  # user-approved plan (may differ from generated)
    session_cookies: str = ""   # "name=value; name2=value2"
    auth_header: str = ""       # "Bearer eyJ..."
    scan_mode: str = "auto"     # auto | ip | api | source_code
    api_spec_url: str = ""      # OpenAPI/Swagger spec URL or local path
    repo_url: str = ""          # git repo URL for source_code mode


class ScanJob(BaseModel):
    id: str
    program_id: str
    status: ScanStatus = ScanStatus.pending
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    findings_count: int = 0
    reports_count: int = 0
    session_cookies: str = ""
    auth_header: str = ""
    scan_mode: str = "auto"       # auto | ip | api | source_code
    api_spec_url: str = ""
    repo_url: str = ""


# --- Finding ---

class FilterResult(BaseModel):
    approved: bool
    reason: str
    severity: Optional[Severity] = None
    attack_chain: Optional[str] = None


class PocResult(BaseModel):
    confirmed: bool
    evidence: str
    safe_output: str
    request: Optional[str] = None
    response_snippet: Optional[str] = None


class Finding(BaseModel):
    id: str
    scan_id: str
    program_id: str
    tool: str  # which tool found it
    title: str
    url: str
    severity: Severity
    vuln_type: str
    raw_output: str
    http_evidence: Optional[str] = None  # JSON-encoded evidence from capture_finding_evidence()
    filter_result: Optional[FilterResult] = None
    poc_result: Optional[PocResult] = None
    report_path: Optional[str] = None
    created_at: datetime = datetime.utcnow()


# --- Report ---

class Report(BaseModel):
    id: str
    finding_id: str
    program_id: str
    markdown: str
    title: str
    severity: Severity
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    created_at: datetime = datetime.utcnow()


# --- API responses ---

class ApiResponse(BaseModel):
    success: bool
    data: Optional[dict] = None
    error: Optional[str] = None


# --- History / DB models ---

class HistoryProgram(BaseModel):
    id: str
    name: str
    created_at: Optional[str] = None
    scan_count: int = 0
    total_findings: int = 0
    total_reports: int = 0
    last_scan_at: Optional[str] = None


class HistoryScan(BaseModel):
    id: str
    program_id: str
    status: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    findings_count: int = 0
    reports_count: int = 0


class HistoryFinding(BaseModel):
    id: str
    scan_id: str
    title: str
    severity: str
    vuln_type: str
    target: str
    passed_filter: int = 0
    created_at: Optional[str] = None
