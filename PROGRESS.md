# PROGRESS — Bug Bounty Assistant

> This file is the source of truth for Claude Code sessions.
> Read this first. It tells you exactly what is done and what to build next.

---

## Current status: v2 WORKING — Full scan pipeline operational

**Phase**: Active development — v2 improvements
**What exists**: Fully implemented backend + frontend — the entire scan pipeline runs end-to-end
**What works**: Everything. Real scans against real programs. AI-filtered findings. Report generation.
**Last tested**: Telegram wallet program (walletbot.me) — 5 live hosts, 1604 URLs, 15 min full scan

---

## Completed ✅

### Infrastructure
- [x] Docker Compose + Dockerfile (all Go tools installed)
- [x] Redis event streaming (SSE for live scan progress)
- [x] FastAPI backend with zombie-scan detection on restart
- [x] React frontend — full routing, terminal-style scan UI

### Backend services (all fully implemented)
- [x] `claude_service.py` — scope parsing, plan generation, finding filter, PoC validation, report generation
- [x] `scope_parser.py` — domain/URL scope matching, wildcard support, excluded vuln type detection
- [x] `passive_recon.py` — crt.sh, Wayback CDX, VirusTotal, URLScan, OTX (key-optional)
- [x] `tool_runner.py` — all 13 tools via asyncio subprocess
- [x] `finding_filter.py` — 3-layer filter (scope → Claude AI → PoC)
- [x] `poc_validator.py` — automated PoC confirmation
- [x] `report_generator.py` — HackerOne-ready markdown reports

### Full scan pipeline (all phases implemented)
- [x] Phase 1: Passive recon (crt.sh, Wayback, VirusTotal, URLScan, OTX) — parallel per apex domain
- [x] Phase 2: Active recon — subfinder → dnsx → nmap (non-standard ports) → httpx → gau → katana
- [x] Phase 2.5: Content discovery — ffuf (top 5 hosts, 200/403 tracking)
- [x] Phase 2.6: JS secret scanning — regex on up to 200 .js files
- [x] Phase 2.7: 403 bypass testing — header + path tricks
- [x] Phase 2.8: Parameter discovery — arjun (5 endpoints, 120s cap)
- [x] Phase 2.9: CORS misconfiguration check — 4 attack patterns on 60 live URLs
- [x] Phase 2.10: Subdomain takeover — 30 provider fingerprints on up to 200 subdomains
- [x] Phase 3: Nuclei scan — 6 high-value template subdirs, smart URL selection (max 500)
- [x] Phase 3.1: GitHub dorking — domain + org queries, placeholder filtering
- [x] Phase 4: SQLi validation — sqlmap time-based blind on nuclei candidates
- [x] Phase 5: AI filtering — Claude 3-layer filter (scope → impact → PoC)
- [x] Phase 6: Report generation — Claude-written H1-ready markdown

### Intelligence & safety
- [x] Program-type adaptation (web/api/mobile/blockchain skips irrelevant phases)
- [x] "No automated scanner" keyword detection → nuclei disabled
- [x] X-HackerOne-Researcher header on all outbound tool traffic
- [x] CDN-aware nmap (expands Cloudflare IPs → all hostnames)
- [x] GAU dedup + per-domain cap (10k URLs, 5 apex domains)
- [x] httpx fallback chain (explicit scope URLs → generated domain URLs)
- [x] Nuclei progress ticker (keeps SSE alive during 15-min scans)
- [x] Zombie scan detection on reconnect
- [x] Credential-in-URL detection (GAU output, RFC-3986 + path patterns)

### Frontend (all fully implemented)
- [x] `ProgramInput.jsx` — paste scope, submit, store to Redis
- [x] `PlanReview.jsx` — show generated plan, approve button
- [x] `ScanProgress.jsx` — live terminal SSE output, status bar, phase labels
- [x] `FindingsList.jsx` — filtered findings with severity badges
- [x] `ReportViewer.jsx` — markdown renderer + copy button
- [x] `ReportsList.jsx` — all reports per program
- [x] `ProgramsList.jsx` — saved programs list

---

## v2 Improvements — In progress 🔧

### ✅ Done in this session
- [x] PROGRESS.md updated to reflect real state
- [x] Tech stack detection from httpx results (`extract_tech_stack`)
- [x] Nuclei CVE second-pass with tech-specific tags (separate 90s bounded run)
- [x] `tech_detected` event pushed to frontend with detected stack
- [x] UI: `tool_skip` event handled and displayed
- [x] UI: `pipeline_config` event displayed (shows what phases are enabled)
- [x] UI: `tech_detected` event displayed prominently
- [x] UI: `finding_error` event handled
- [x] UI: `passive_recon_detail` added to PHASE_LABELS
- [x] UI: `sqli_validation` added to PHASE_LABELS
- [x] Anthropic model router with task-specific models + fallback chain
- [x] LLM usage accounting (calls/tokens/estimated USD) in `claude_service`
- [x] Scan pipeline now emits `llm_usage` SSE event on completion/failure
- [x] UI: `llm_usage` event displayed + live "LLM Cost" status field
- [x] Expanded no-automation policy keyword detection (`manual preferred` / `refrain` variants)
- [x] Added unit tests for model chain + usage delta logic (`backend/tests/test_claude_routing.py`)
- [x] Persisted per-scan `llm_cost_usd` in SQLite (`scans` table) with backward-compatible migration
- [x] History API/UX now shows aggregated and per-scan LLM cost
- [x] Extracted automation-policy matcher to `backend/services/policy_rules.py`
- [x] Extracted passive target selection to `backend/services/scan_targets.py`
- [x] Extracted passive recon orchestration to `backend/services/phases/passive_recon_phase.py`
- [x] Extracted active recon core (subfinder/dnsx/nmap) to `backend/services/phases/active_recon_phase.py`
- [x] Extracted URL recon phase (httpx/fallbacks/gau/katana/cred detection) to `backend/services/phases/url_recon_phase.py`
- [x] Extracted GitHub dork phase to `backend/services/phases/github_dork_phase.py`
- [x] Extracted content discovery + JS scanning phase to `backend/services/phases/content_and_js_phase.py`
- [x] Extracted appsec probe phase (403 bypass + arjun + dalfox) to `backend/services/phases/appsec_probe_phase.py`
- [x] Extracted security surface phase (cors/takeover/email/swagger/s3) to `backend/services/phases/security_surface_phase.py`
- [x] Extracted finding aggregation helpers to `backend/services/phases/finding_aggregation_phase.py`
- [x] Extracted filtering/reporting phase (sqli validation + filter + report generation) to `backend/services/phases/filtering_reporting_phase.py`
- [x] Extracted non-web pipeline phase (ip/source_code/api modes) to `backend/services/phases/non_web_pipeline_phase.py`
- [x] Extracted scan finalization helpers (done/failed status + LLM usage + notifications) to `backend/services/phases/scan_finalize_phase.py`
- [x] Extracted raw findings persistence for non-web pipelines to `backend/services/phases/persist_raw_findings_phase.py`
- [x] Extracted pipeline mode/policy resolver (auto mode + feature toggles) to `backend/services/phases/pipeline_mode_phase.py`
- [x] Extracted delta history flow (baseline load, new surface diff, history save) to `backend/services/phases/delta_history_phase.py`
- [x] Extracted full web pipeline orchestration (Phase 1 passive → Phase 4 filter) to `backend/services/phases/web_pipeline_phase.py`; also moved `select_nuclei_targets`, `select_ffuf_targets`, `nuclei_to_finding` there; `_run_scan_pipeline` in `scans.py` reduced to ~50 lines
- [x] Extracted httpx target and generated fallback URL helpers in `backend/services/scan_targets.py`
- [x] Replaced in-router GAU apex dedupe with shared `select_passive_domains` helper
- [x] Added tests for policy matcher and passive target selector
- [x] Added active recon phase unit test scaffold (`backend/tests/test_active_recon_phase.py`)
- [x] Added URL recon phase unit test scaffold (`backend/tests/test_url_recon_phase.py`)
- [x] Added GitHub dork phase unit test scaffold (`backend/tests/test_github_dork_phase.py`)
- [x] Added content/js phase unit test scaffold (`backend/tests/test_content_and_js_phase.py`)
- [x] Added appsec probe phase unit test scaffold (`backend/tests/test_appsec_probe_phase.py`)
- [x] Added security surface phase unit test scaffold (`backend/tests/test_security_surface_phase.py`)
- [x] Added finding aggregation phase unit test scaffold (`backend/tests/test_finding_aggregation_phase.py`)
- [x] Added filtering/reporting phase unit test scaffold (`backend/tests/test_filtering_reporting_phase.py`)
- [x] Added non-web pipeline phase unit test scaffold (`backend/tests/test_non_web_pipeline_phase.py`)
- [x] Added scan finalization phase unit test scaffold (`backend/tests/test_scan_finalize_phase.py`)
- [x] Added raw findings persistence phase unit test scaffold (`backend/tests/test_persist_raw_findings_phase.py`)
- [x] Added pipeline mode phase unit test scaffold (`backend/tests/test_pipeline_mode_phase.py`)
- [x] Added delta history phase unit test scaffold (`backend/tests/test_delta_history_phase.py`)
- [x] Added web pipeline phase unit test scaffold (`backend/tests/test_web_pipeline_phase.py`)

### Next improvements to make
- [ ] **Nuclei template curator** — detect WordPress/Jenkins/Jira and run targeted CVE subdirs
- [ ] **Wappalyzer-style detection** — use httpx `tech` field to show tech stack in UI
- [ ] **Program history** — list past scans per program with finding counts
- [ ] **Scan comparison** — diff findings between two scans of same program
- [ ] **Rate limit config** — per-program custom rate limits (some programs allow 100 req/s)
- [ ] **Manual finding entry** — add findings found manually (not from scanner)
- [ ] **Re-run single phase** — restart just nuclei or just JS scan without full re-scan

---

## Known gaps / limitations

| Gap | Impact | Fix needed |
|---|---|---|
| No authenticated scanning | Misses /api/ endpoints behind auth | Add cookie/JWT injection to httpx/katana |
| nuclei CVE templates = years-based dirs | Can't target specific tech CVEs cleanly | Tech-tag based second pass (now added) |
| arjun still slow on some targets | 5 × 120s = 10 min worst case | Already capped; acceptable |
| GitHub dork rate limit (30 req/min) | Slow for 2+ domains | Already capped at 2 apex domains |
| No APK/mobile analysis | Misses mobile-only programs | Future: MobSF integration |

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
| 500 URL cap for nuclei | >500 → scan takes >30 min with diminishing returns |
| Separate CVE second-pass for nuclei | Avoids -tags globally filtering all template dirs |

---

## Lessons from rejected reports (critical context)

**OPPO rejected** — Missing HSTS report:
- Reason: "no significant security impact", "best practice not a vulnerability"
- Fix: filter ALL missing-header findings unless chained to real exploit ✅ (Claude filter handles this)

**PayPal rejected** — 10 findings from scanner:
- Reason: "automated scanner output", "no working PoC", "not exploitable"
- Fix: NEVER submit scanner output directly; PoC required ✅ (Layer 3 handles this)
- Items that were out of scope per PayPal rules: missing CSP, HttpOnly, SameSite, DKIM, Referrer-Policy, Permissions-Policy ✅ (excluded_vuln_types filter)

**Rule**: If the program's "Out of scope" section lists it → automatically drop finding, never show user.

---

## How to run

```bash
docker-compose up --build
# Backend: http://localhost:8000
# Frontend: http://localhost:3000
# API docs: http://localhost:8000/docs
```

## Environment variables

See `.env.example` — minimum required is `ANTHROPIC_API_KEY`.
Optional: `GITHUB_TOKEN` (GitHub dorking), `VIRUSTOTAL_API_KEY`, `URLSCAN_API_KEY`, `OTX_API_KEY`.

---

## File to read before each Claude Code session

1. This file (PROGRESS.md)
2. ARCHITECTURE.md (system design)
3. The specific file you're working on
