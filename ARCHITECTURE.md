# Architecture — Bug Bounty Assistant

## System overview

```
User (browser) ←→ React UI ←→ FastAPI Backend ←→ Claude API
                                    ↓
                              Redis (job queue)
                                    ↓
                         Tool Runner (subprocess)
                         ├── Go tools (nuclei, subfinder...)
                         └── Passive APIs (crt.sh, VT...)
                                    ↓
                           workspace/{program}/
```

## Request lifecycle

```
1. POST /api/programs          — save program text
2. POST /api/programs/{id}/plan — Claude parses scope + generates plan
3. GET  /api/programs/{id}/plan — user reviews plan
4. POST /api/scans/start       — user approves → scan job enqueued
5. GET  /api/scans/{id}/stream — SSE stream of live tool output
6. GET  /api/scans/{id}/findings — filtered, validated findings
7. POST /api/reports/{finding_id} — Claude generates markdown report
8. GET  /api/reports/{id}      — download final report
```

## Three-layer finding filter (CRITICAL)

Every finding from every tool must pass all three layers before the user sees it.

### Layer 1 — Scope compliance
```python
def check_scope(finding, scope) -> bool:
    # Is target domain in scope?
    # Is vuln type explicitly excluded by program?
    # Is endpoint in allowed list?
```

Auto-drop if any of these:
- Target domain not in `scope.in_scope_domains`
- Finding type matches anything in `scope.excluded_vuln_types`
- Common excluded types (present in most programs):
  - missing security headers (HSTS, CSP, X-Content-Type-Options, etc.)
  - missing cookie flags (HttpOnly, SameSite, Secure)
  - missing email auth (SPF, DKIM, DMARC)
  - software version disclosure
  - clickjacking without sensitive action
  - open redirect without chained impact
  - rate limiting on non-auth endpoints
  - self-XSS
  - CSV injection without PoC
  - tabnabbing

### Layer 2 — Impact assessment (Claude)
```python
async def assess_impact(finding) -> ImpactAssessment:
    # Claude evaluates:
    # - Is there a realistic attack scenario?
    # - Can this lead to: data breach, account takeover, RCE, financial loss?
    # - Is the impact on OTHER users (not just self)?
    # Returns: {has_impact: bool, severity: str, attack_chain: str}
```

Reject if `has_impact = False`.

### Layer 3 — PoC validation
```python
async def validate_poc(finding) -> PocResult:
    # Attempt to confirm the finding with a safe, non-destructive request
    # For XSS: inject payload, check if reflected/stored
    # For SSRF: use interactsh callback, confirm DNS/HTTP hit
    # For SQLi: use time-based or error-based, confirm response diff
    # For IDOR: check if another user's resource is returned
    # Returns: {confirmed: bool, evidence: str, safe_output: str}
```

If `confirmed = False` → move to "manual review" bucket, not auto-report.

## Workspace structure

```
workspace/
└── {program_slug}/
    ├── scope.json          ← parsed scope from Claude
    ├── plan.md             ← generated testing plan
    ├── recon/
    │   ├── subdomains.txt  ← subfinder + crt.sh output
    │   ├── live_hosts.txt  ← httpx output
    │   ├── urls.txt        ← gau + wayback + katana output
    │   └── ports.json      ← nmap output
    ├── scans/
    │   ├── nuclei.json     ← raw nuclei output
    │   ├── ffuf.json       ← directory fuzzing
    │   ├── dalfox.json     ← XSS results
    │   └── params.json     ← arjun parameter discovery
    ├── findings/
    │   ├── raw/            ← all unfiltered findings
    │   ├── filtered/       ← passed all 3 layers
    │   └── rejected/       ← filtered out (with reason)
    └── reports/
        └── {finding_id}.md ← final H1-ready report
```

## Claude service — prompt strategy

### Scope parsing prompt
- Input: raw program text (as pasted from H1)
- Output: structured JSON with in_scope, out_of_scope, excluded_vulns, test_endpoints
- Temperature: 0 (deterministic)

### Plan generation prompt
- Input: parsed scope JSON
- Output: ordered list of tool commands with rationale
- Adapts based on program type (web/api/blockchain/mobile)
- Temperature: 0.3

### Finding filter prompt (most critical)
- Input: raw finding + scope + program rules
- Strict system prompt: "You are a senior bug bounty hunter. Only approve findings that..."
  - Have a clear attack chain ending in business impact
  - Affect other users or the organization (not just self)
  - Are NOT in the program's excluded list
  - Are exploitable from a realistic attacker position
- Output: {approved: bool, reason: str, severity: str, attack_chain: str}
- Temperature: 0

### Report generation prompt
- Input: validated finding + PoC evidence + program rules
- Output: markdown following H1 report format
- Includes: Title, Severity, CVSS, Summary, Steps to Reproduce, Impact, PoC, Remediation
- Temperature: 0.5

## Tool execution order

```
Phase 1 — Passive (no direct contact with target)
  crt.sh → Wayback CDX → VirusTotal passive DNS → URLScan lookup

Phase 2 — Active recon (light touch, observe only)
  subfinder → dnsx → httpx → gau → katana

Phase 3 — Scanning (targeted, scope-limited)
  nmap (light) → nuclei → arjun → ffuf

Phase 4 — Validation (only on interesting findings)
  dalfox (if XSS candidate) → sqlmap (if SQLi candidate) → interactsh (if SSRF candidate)

Phase 5 — Report
  Claude generates markdown for each confirmed finding
```

## Nuclei template strategy

Nuclei has 9000+ templates. Most are noise for bug bounty.
The tool runs nuclei with a curated tag filter:

**Run these tags**: `rce,sqli,xss,ssrf,lfi,idor,auth-bypass,exposed-panel,default-creds,exposed-api,token-disclosure,jwt,graphql,xxe,ssti,open-redirect,cve`

**Skip these tags**: `ssl,headers,cors,cookies,tech,info,dns,misconfig` (mostly informative / out of scope)

Custom filter: `backend/services/nuclei_filter.py` maps raw nuclei severity to H1 severity and applies program rules.

## API design

All endpoints return consistent envelope:
```json
{
  "success": true,
  "data": {...},
  "error": null
}
```

WebSocket/SSE for scan progress: `GET /api/scans/{id}/stream`
Sends newline-delimited JSON events:
```json
{"type": "tool_start", "tool": "subfinder", "target": "example.com"}
{"type": "tool_output", "line": "sub.example.com"}
{"type": "finding", "severity": "high", "title": "SQL Injection in /api/search"}
{"type": "tool_done", "tool": "subfinder", "found": 42}
{"type": "scan_done", "findings": 3, "reports": 2}
```
