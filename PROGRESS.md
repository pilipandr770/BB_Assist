# PROGRESS — Bug Bounty Assistant

> This file is the source of truth for Claude Code sessions.
> Read this first. It tells you exactly what is done and what to build next.

---

## Current status: SKELETON COMPLETE — Ready for implementation

**Phase**: Phase 1 of 3
**What exists**: Full project structure + all configuration + skeleton code with TODO markers
**What works**: Nothing yet (no implementation)
**Next action**: Implement backend services (start from `claude_service.py`)

---

## Completed ✅

- [x] Project structure and all directories
- [x] Docker Compose + Dockerfile (tools installation)
- [x] `.env.example` with all keys documented
- [x] `backend/config.py` — settings
- [x] `backend/models.py` — all Pydantic models
- [x] `backend/main.py` — FastAPI app skeleton with routes registered
- [x] `backend/routers/programs.py` — route handlers (bodies are TODO)
- [x] `backend/routers/scans.py` — route handlers (bodies are TODO)
- [x] `backend/routers/reports.py` — route handlers (bodies are TODO)
- [x] `backend/services/claude_service.py` — prompts defined, API calls are TODO
- [x] `backend/services/scope_parser.py` — logic skeleton (TODO)
- [x] `backend/services/passive_recon.py` — API integrations skeleton (TODO)
- [x] `backend/services/tool_runner.py` — subprocess runner skeleton (TODO)
- [x] `backend/services/finding_filter.py` — 3-layer filter skeleton (TODO)
- [x] `backend/services/poc_validator.py` — PoC validation skeleton (TODO)
- [x] `backend/services/report_generator.py` — report builder skeleton (TODO)
- [x] `frontend/src/App.jsx` — routing skeleton
- [x] `frontend/src/components/` — all 5 components skeleton
- [x] All docs (ARCHITECTURE.md, WORKFLOW.md, TOOLS.md, APIS.md, REPORT_FORMAT.md)

---

## Phase 1 — Backend core (implement next) 🔧

### Step 1: `backend/services/claude_service.py`
This is the brain. Implement all Claude API calls.
- `parse_scope(program_text)` → structured scope JSON
- `generate_plan(scope)` → testing plan with tool commands
- `filter_finding(finding, scope)` → is this worth reporting?
- `validate_poc(finding, poc_output)` → does the PoC prove real impact?
- `generate_report(finding)` → H1-ready markdown

**Key constraint**: The filter must be strict. Re-read ARCHITECTURE.md section "Three-layer filter".
The lesson from rejected reports: HSTS missing = reject, missing CSP = reject, missing headers = reject.
Only findings with demonstrated exploitation chain get through.

### Step 2: `backend/services/scope_parser.py`
Parse raw H1 program text into structured scope.
Output must include:
- `in_scope_domains: list[str]`
- `in_scope_urls: list[str]`
- `out_of_scope_domains: list[str]`
- `excluded_vuln_types: list[str]` (parse "Out of scope vulnerabilities" section)
- `allowed_test_endpoints: list[str]`
- `program_type: str` (web, api, blockchain, mobile, etc.)

### Step 3: `backend/services/passive_recon.py`
Implement all free API calls. No key needed for crt.sh and Wayback.
Order: crt.sh → Wayback CDX → IPInfo → VirusTotal (if key) → URLScan (if key) → OTX (if key)
Always check if API key exists before calling keyed APIs.

### Step 4: `backend/services/tool_runner.py`
Run Go tools via asyncio subprocess.
Critical: always pass scope to every tool call — never scan out-of-scope targets.
Stream stdout to Redis so frontend can show live progress.

### Step 5: `backend/services/finding_filter.py`
Three layers:
1. Scope check (in-scope domain? allowed vuln type?)
2. Value check (has Claude said this has real impact?)
3. PoC check (did poc_validator confirm it?)
Only pass all three → becomes a report candidate.

### Step 6: Routers (after services work)
Wire up the service calls into the route handlers.
Test each endpoint with curl before moving to frontend.

---

## Phase 2 — Frontend 🎨

Start only after backend API is fully working.

Components to implement in order:
1. `ProgramInput.jsx` — textarea + submit, call POST /api/programs
2. `PlanReview.jsx` — show plan, approve button, call POST /api/scans/start
3. `ScanProgress.jsx` — WebSocket or SSE for live tool output
4. `FindingsList.jsx` — show filtered findings with severity badges
5. `ReportViewer.jsx` — markdown renderer + copy button

---

## Phase 3 — Testing & tuning 🧪

- Test against Circle BBP (Arc testnet — the program from initial session)
- Test against OPPO (learn from the rejected HSTS report)
- Tune Claude filter prompts based on real results
- Add nuclei template filtering (suppress noisy low-value templates)

---

## Key decisions made (don't re-debate these)

| Decision | Rationale |
|---|---|
| Python FastAPI backend | Easier subprocess management, Claude SDK, faster iteration |
| Go tools via subprocess | Best-in-class tools, all free, widely used in bug bounty |
| Redis for job queue | Simple, Docker-native, handles async scan jobs |
| Markdown reports, manual H1 submit | Program triagers give real-time feedback on H1 form |
| English UI | Standard for security tooling |
| Three-layer filter before report | Learned from rejected reports: no scanner dumps |
| Free APIs only for now | crt.sh/Wayback = no key, others = free tier |
| No Burp/Metasploit | GUI tools, can't automate well; Go tools are better |

---

## Lessons from rejected reports (critical context)

**OPPO rejected** — Missing HSTS report:
- Reason: "no significant security impact", "best practice not a vulnerability"
- Fix in tool: filter ALL missing-header findings unless chained to real exploit

**PayPal rejected** — 10 findings from scanner:
- Reason: "automated scanner output", "no working PoC", "not exploitable"
- Fix in tool: NEVER submit scanner output directly
- Items that were out of scope per PayPal rules: missing CSP, HttpOnly, SameSite, DKIM, Referrer-Policy, Permissions-Policy — all filtered

**Rule**: If the program's "Out of scope" section lists it → automatically drop finding, never show user.

---

## How to run (when implemented)

```bash
docker-compose up --build
# Backend: http://localhost:8000
# Frontend: http://localhost:3000
# API docs: http://localhost:8000/docs
```

## Environment variables needed

See `.env.example` — minimum required is only `ANTHROPIC_API_KEY`.
All other API keys are optional (tool degrades gracefully without them).

---

## File to read before each Claude Code session

1. This file (PROGRESS.md)
2. ARCHITECTURE.md (system design)
3. The specific service file you're implementing
