# Bug Bounty Assistant

> AI-powered, scope-aware vulnerability research tool for HackerOne bug bounty programs.
> Built for personal use. Runs locally via Docker.

## What it does

1. **You paste** the HackerOne program scope/conditions
2. **Claude analyzes** scope, generates a targeted testing plan
3. **You approve** the plan before anything runs
4. **Tools run automatically** — recon → scan → validate
5. **Three-layer filter** removes out-of-scope and low-value findings
6. **Claude writes** a HackerOne-ready markdown report with PoC

## Core principle

> Only report findings with a **complete exploitation chain** and a **working PoC**.
> No scanner dumps. No missing-header reports. No informatives.

## Stack

- **Backend**: Python 3.12 + FastAPI + Redis (job queue)
- **Frontend**: React + Vite (English UI)
- **AI**: Claude claude-sonnet-4-20250514 via Anthropic API
- **Recon/Scan tools**: Go binaries (subfinder, httpx, nuclei, ffuf, dalfox, katana, gau, dnsx, interactsh, arjun, nmap)
- **Passive APIs**: crt.sh, Wayback CDX, VirusTotal, URLScan.io, AlienVault OTX, IPInfo.io
- **Runtime**: Docker Compose

## Quick start

```bash
# 1. Clone / copy project
cd bug-bounty-assistant

# 2. Configure environment
cp .env.example .env
# Edit .env — add ANTHROPIC_API_KEY and optional API keys

# 3. Build and run
docker-compose up --build

# 4. Open browser
open http://localhost:3000
```

## Workflow

```
Paste program scope → Claude plan → Approve → Auto scan → Filter → PoC → Markdown report
```

See [docs/WORKFLOW.md](docs/WORKFLOW.md) for detailed flow.
See [docs/TOOLS.md](docs/TOOLS.md) for tool descriptions and flags.
See [PROGRESS.md](PROGRESS.md) for current implementation status.

## Project structure

```
bug-bounty-assistant/
├── backend/              # FastAPI backend
│   ├── main.py           # App entry point + routes
│   ├── config.py         # Settings from .env
│   ├── models.py         # Pydantic models
│   ├── routers/          # API route handlers
│   └── services/         # Business logic
│       ├── claude_service.py    # All Claude API calls
│       ├── scope_parser.py      # Parse H1 program conditions
│       ├── passive_recon.py     # Free API integrations
│       ├── tool_runner.py       # Run Go tools via subprocess
│       ├── finding_filter.py    # 3-layer finding filter
│       ├── poc_validator.py     # Confirm PoC works
│       └── report_generator.py  # H1-ready markdown output
├── frontend/             # React UI
│   └── src/
│       ├── App.jsx
│       └── components/
│           ├── ProgramInput.jsx   # Paste scope here
│           ├── PlanReview.jsx     # Review + approve plan
│           ├── ScanProgress.jsx   # Live tool output
│           ├── FindingsList.jsx   # Validated findings
│           └── ReportViewer.jsx   # Final markdown report
├── docs/                 # Documentation
├── workspace/            # Scan results (gitignored)
├── .env.example
├── docker-compose.yml
└── Dockerfile
```

## Legal / Ethics

- Testing is performed **only against program-approved targets**
- Scope is parsed and enforced automatically — out-of-scope targets are blocked
- No real exploitation — PoC confirms vulnerability exists, does not cause damage
- Complies with HackerOne program rules and responsible disclosure
- For personal use only
