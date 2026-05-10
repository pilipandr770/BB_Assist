# Roadmap — Bug Bounty Assistant

## Phase 1 — Core backend (current)
**Goal**: Working API that can scan a target and produce a validated finding

- [ ] Implement `claude_service.py` (all 5 Claude calls)
- [ ] Implement `scope_parser.py`
- [ ] Implement `passive_recon.py` (crt.sh + Wayback free tier first)
- [ ] Implement `tool_runner.py` (subfinder + httpx + nuclei first)
- [ ] Implement `finding_filter.py` (all 3 layers)
- [ ] Implement `report_generator.py`
- [ ] Wire up all routers
- [ ] Test with Circle BBP (Arc testnet) — blockchain scope
- [ ] Test with a web scope program

**Success criteria**: Tool runs on a real program, produces at least one valid finding that would not get rejected as "informative"

---

## Phase 2 — Frontend
**Goal**: Usable UI, no more curl commands

- [ ] `ProgramInput.jsx` — paste scope, submit
- [ ] `PlanReview.jsx` — show plan, approve
- [ ] `ScanProgress.jsx` — live output via SSE
- [ ] `FindingsList.jsx` — filtered findings with badges
- [ ] `ReportViewer.jsx` — markdown view + copy

---

## Phase 3 — Intelligence & tuning
**Goal**: Higher signal-to-noise, smarter targeting

- [ ] Nuclei template curator — auto-select templates based on detected tech stack
- [ ] Paid API support (Shodan, SecurityTrails, Censys) — add when budget allows
- [ ] Program database — remember which programs were tested, findings history
- [ ] Severity trend — track what gets accepted/rejected and learn
- [ ] Custom nuclei templates for common H1 patterns
- [ ] Burp Suite integration (headless, for authenticated scanning)

---

## Phase 4 — Advanced
**Goal**: Handle complex scenarios

- [ ] Authenticated scanning (session cookies, API keys from target)
- [ ] Mobile app scope (APK analysis with MobSF)
- [ ] Source code analysis (for open-source targets like Arc/Circle)
- [ ] Smart rate limiting per program rules
- [ ] Collaborative mode (multiple targets in parallel)

---

## Nice-to-have (future)
- Browser extension to auto-import H1 program scope
- Report versioning (track edits after H1 feedback)
- CVSS calculator UI
- Automatic CVSS from finding type + context
