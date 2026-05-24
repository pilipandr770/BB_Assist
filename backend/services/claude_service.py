"""
Claude service — all AI calls for the bug bounty assistant.

Five functions:
  1. parse_scope()       — extract structured scope from raw H1 program text
  2. generate_plan()     — create ordered testing plan from scope
  3. filter_finding()    — decide if a finding is worth reporting (strict)
  4. validate_poc()      — assess if PoC evidence confirms real impact
  5. generate_report()   — produce HackerOne-ready markdown report
"""

import json
import logging
import re
import anthropic
from backend.config import settings
from backend.models import Scope, Finding, FilterResult, PocResult, Severity

client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
MODEL = "claude-sonnet-4-6"
log = logging.getLogger("claude_service")


def _strip_json(text: str) -> str:
    """
    Extract a JSON object from Claude's response.

    Handles:
    1. Clean JSON — returned as-is
    2. Markdown code fences  — ```json ... ``` stripped
    3. JSON embedded in prose — find first { and matching closing } and extract
    """
    text = text.strip()
    if not text:
        return text

    # Strip markdown code fences
    if text.startswith("```"):
        lines = text.split("\n")
        inner = lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
        text = "\n".join(inner).strip()

    # If it already looks like valid JSON, return it
    if text.startswith("{"):
        return text

    # Last resort: find the first { and the last } and extract the substring.
    # Handles cases where Claude prepends an explanation before the JSON object.
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start:end + 1]

    return text


def _extract_balanced_json_object(text: str) -> str:
    """Extract first balanced top-level JSON object from text, if present."""
    if not text:
        return text
    start = text.find("{")
    if start == -1:
        return text

    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return text


def _parse_scope_json_or_none(raw: str) -> dict | None:
    candidates = [
        _strip_json(raw),
        _extract_balanced_json_object(_strip_json(raw)),
        _extract_balanced_json_object(raw),
    ]
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            continue
    return None


def _fallback_scope_from_text(raw_program_text: str) -> Scope:
    # Conservative fallback so API never returns 500 on parse noise.
    domain_re = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
    ignored = {
        "hackerone.com", "disclose.io", "xss.ht", "owasp.org",
        "github.com", "cvss.org", "cve.org",
        "bugcrowd.com", "intigriti.com", "yeswehack.com", "huntr.com",
    }

    def _is_ignored_domain(domain: str) -> bool:
        d = domain.lower().strip().lstrip("*.")
        return any(d == base or d.endswith("." + base) for base in ignored)

    counts: dict[str, int] = {}
    for m in domain_re.finditer(raw_program_text or ""):
        d = m.group(0).lower()
        if _is_ignored_domain(d):
            continue
        counts[d] = counts.get(d, 0) + 1

    in_scope_domains: list[str] = []
    if counts:
        primary = sorted(counts, key=lambda d: counts[d], reverse=True)[0]
        in_scope_domains = [primary, f"*.{primary}"]

    lower = (raw_program_text or "").lower()
    program_type = "web"
    if "graphql" in lower or "api" in lower:
        program_type = "api"
    if "android" in lower or "ios" in lower or "mobile" in lower:
        program_type = "mobile"
    if "smart contract" in lower or "blockchain" in lower:
        program_type = "blockchain"
    if "source code" in lower or "repository" in lower:
        program_type = "source_code"

    return Scope(
        in_scope_domains=in_scope_domains,
        in_scope_urls=[],
        out_of_scope_domains=[],
        excluded_vuln_types=[],
        allowed_test_endpoints=[],
        program_type=program_type,
        notes="Fallback scope used because AI returned malformed JSON.",
    )


async def parse_scope(raw_program_text: str) -> Scope:
    """
    Parse raw HackerOne program text into structured Scope object.
    Temperature 0 — deterministic extraction.
    """
    prompt = f"""You are a security researcher parsing a HackerOne bug bounty program's scope.

Extract the scope information from the following program text and return it as valid JSON matching this exact schema:
{{
    "in_scope_domains": ["list of in-scope domains/wildcards like *.example.com"],
    "in_scope_urls": ["specific in-scope URLs if listed"],
    "out_of_scope_domains": ["explicitly out-of-scope domains"],
    "excluded_vuln_types": ["vulnerability types the program explicitly says they do NOT want reported, in lowercase"],
    "allowed_test_endpoints": ["specific endpoints explicitly allowed for testing"],
    "program_type": "web|api|blockchain|mobile|source_code",
    "notes": "important notes about program rules, responsible disclosure requirements, etc."
}}

Guidelines:
- program_type: "web" for standard web apps, "api" if primarily API-focused, "blockchain" for smart contracts, "mobile" if mobile apps are primary scope, "source_code" for code review
- Extract ALL exclusions from any "Out of scope" or "Not eligible" sections
- Include wildcard domains as-is (e.g., *.example.com)
- Lowercase all excluded_vuln_types entries
- Return ONLY valid JSON, no markdown, no explanation

CRITICAL — Domain extraction rules:
1. If the program explicitly lists domains or wildcards (e.g. *.example.com), include them ALL
2. If no domains are explicitly listed, INFER the primary domain from: the company name in the program title, email addresses mentioned (e.g. support@wickr.com → wickr.com), URLs referenced in the text, or the product name
3. For software/app programs (mobile, desktop) that don't list web domains, still include the company's primary web domain (e.g. company.com) and *.company.com — this is needed for recon even when the primary scope is the app
4. NEVER return an empty in_scope_domains list — always include at least the apex domain

Program text:
{raw_program_text}"""

    message = await client.messages.create(
        model=MODEL,
        max_tokens=4000,
        temperature=0,
        messages=[{"role": "user", "content": prompt}],
    )

    raw_text = message.content[0].text if message.content else ""
    data = _parse_scope_json_or_none(raw_text)
    if data is not None:
        return Scope(**data)

    # Retry once with explicit correction request using the previous invalid output.
    repair_prompt = (
        "Convert this text into STRICT valid JSON for the exact scope schema. "
        "Output JSON only, no prose, no markdown:\n\n"
        f"{raw_text[:5000]}"
    )
    repair_message = await client.messages.create(
        model=MODEL,
        max_tokens=2000,
        temperature=0,
        messages=[{"role": "user", "content": repair_prompt}],
    )
    repair_raw = repair_message.content[0].text if repair_message.content else ""
    repaired = _parse_scope_json_or_none(repair_raw)
    if repaired is not None:
        return Scope(**repaired)

    log.warning(
        "parse_scope fallback activated: unparseable model output (first_len=%d, retry_len=%d)",
        len(raw_text),
        len(repair_raw),
    )
    return _fallback_scope_from_text(raw_program_text)


async def generate_plan(scope: Scope, raw_program_text: str) -> str:
    """
    Generate a markdown testing plan based on parsed scope.
    Temperature 0.3 — structured but adapts to program type.
    """
    scope_json = scope.model_dump_json(indent=2)

    prompt = f"""You are an expert bug bounty hunter. Create a detailed, prioritized testing plan for this HackerOne program.

Program scope (structured):
{scope_json}

Raw program text:
{raw_program_text[:4000]}

Generate a complete markdown testing plan with these phases:

## Phase 1: Passive Recon (Zero contact with target)
List commands using: crt.sh, Wayback CDX API, VirusTotal (if key available), URLScan, OTX
Include exact API endpoints and parameters.

## Phase 2: Active Recon (Safe enumeration)
List exact tool commands for:
- subfinder: subdomain discovery
- dnsx: DNS validation of discovered subdomains
- httpx: live host probing with tech detection
- gau + katana: URL/endpoint discovery
- nmap on non-standard web ports with service detection: use -sC -sV and include output parsing notes

Every command MUST include scope constraints (use only in-scope domains).
Include rate limit flags to stay under radar.

## Phase 3: Vulnerability Scanning
Nuclei command with tags: rce,sqli,xss,ssrf,lfi,idor,auth-bypass,exposed-panel,default-creds,exposed-api,token-disclosure,jwt,graphql,xxe,ssti,open-redirect,cve
Include a version-based CVE check step using a local CSV mapping of service/version fingerprints (from nmap -sV) to candidate CVEs.
Mention that CSV freshness directly impacts detection coverage and should be updated regularly.
ffuf for directory fuzzing on interesting hosts.
arjun for hidden parameter discovery on API endpoints.

## Phase 4: Targeted Validation (Only if candidates found)
- dalfox: only for XSS candidates from nuclei/manual review
- Time-based SQLi: only for SQLi candidates
- interactsh: for SSRF/XXE/blind injection OOB callbacks

## Priority Targets
List high-value endpoints/patterns to prioritize (auth flows, API endpoints, admin panels, file upload, etc.)

## What NOT to Test
Based on the program scope, explicitly list excluded targets and vuln types.

Program type: {scope.program_type}
In-scope domains: {', '.join(scope.in_scope_domains) or 'See notes'}

{'## Blockchain-Specific Steps' if scope.program_type == 'blockchain' else ''}
{'- Review smart contract source code for reentrancy, integer overflow, access control' if scope.program_type == 'blockchain' else ''}

{'## API-Specific Steps' if scope.program_type == 'api' else ''}
{'- Focus on: auth bypass, IDOR, parameter tampering, rate limiting on auth endpoints, mass assignment' if scope.program_type == 'api' else ''}

Return a well-structured, actionable markdown document."""

    message = await client.messages.create(
        model=MODEL,
        max_tokens=6000,
        temperature=0.3,
        messages=[{"role": "user", "content": prompt}],
    )

    return message.content[0].text


async def filter_finding(finding: Finding, scope: Scope, raw_program_text: str) -> FilterResult:
    """
    Strict filter: decide if a finding deserves a H1 report.
    Temperature 0 — never creative, always conservative.
    """
    finding_dict = finding.model_dump()
    scope_dict = scope.model_dump()

    system_prompt = """You are a senior HackerOne triage specialist. Your job is to pre-screen security findings before they waste a triager's time.

REJECT all of the following — programs universally mark these as Informative or N/A:
- Missing security headers: HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-Frame-Options
- Missing cookie flags: HttpOnly, SameSite, Secure
- Missing email authentication: SPF, DKIM, DMARC
- Software version disclosure or banner grabbing
- Rate limiting on non-authentication endpoints
- Self-XSS (only the attacker themselves see the effect)
- CSRF on logout or unauthenticated pages
- Open redirects without a chained, demonstrable impact
- Clickjacking without a sensitive action
- Generic error messages or stack traces (unless they reveal secrets/credentials)
- SSL/TLS configuration issues
- Theoretical attacks with no realistic path
- Anything the program explicitly excludes

APPROVE only if ALL of these are true:
1. Target URL is in scope
2. Vulnerability type is NOT in excluded types
3. There is a complete, realistic attack chain ending in one of: data breach, account takeover, RCE, financial loss, business logic abuse affecting other users
4. The finding affects real users or organizational assets (not just the attacker themselves)
5. A working PoC can demonstrate the impact
6. A triager would NOT close this as Informative

Be EXTREMELY strict. If you have any doubt, REJECT.

Respond with valid JSON only — no markdown, no explanation outside the JSON:
{
    "approved": true or false,
    "reason": "one clear sentence explaining the decision",
    "severity": "critical|high|medium|low|informative",
    "attack_chain": "full attack chain description (only if approved, else null)"
}"""

    user_prompt = f"""Evaluate this finding for HackerOne submission:

Finding:
{json.dumps(finding_dict, default=str, indent=2)}

Program scope:
{json.dumps(scope_dict, indent=2)}

Program rules (first 3000 chars):
{raw_program_text[:3000]}

Decision:"""

    message = await client.messages.create(
        model=MODEL,
        max_tokens=500,
        temperature=0,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    )

    raw_text = ""
    try:
        raw_text = message.content[0].text if message.content else ""
        data = json.loads(_strip_json(raw_text))
    except (json.JSONDecodeError, IndexError, Exception):
        # Claude returned empty/invalid JSON — conservatively reject the finding
        # rather than crashing the entire scan pipeline.
        return FilterResult(
            approved=False,
            reason=f"Claude filter returned unparseable response (len={len(raw_text)}) — conservative rejection",
            severity=Severity.informative,
            attack_chain=None,
        )

    severity = None
    if data.get("severity"):
        try:
            severity = Severity(data["severity"])
        except ValueError:
            severity = Severity.informative

    return FilterResult(
        approved=data.get("approved", False),
        reason=data.get("reason", "No reason provided"),
        severity=severity,
        attack_chain=data.get("attack_chain"),
    )


async def validate_poc(finding: Finding, poc_output: str) -> PocResult:
    """
    Assess whether the PoC evidence confirms a real vulnerability.
    Temperature 0 — conservative, evidence-based judgment only.
    """
    finding_dict = finding.model_dump()

    system_prompt = """You are a senior security researcher reviewing PoC evidence.

CONFIRMED means the output shows unambiguous proof of exploitation:
- XSS: payload appears in response without encoding, or dalfox confirmed execution
- SQLi: real data extracted, error reveals SQL syntax, or time delay >= 5s confirmed
- SSRF: interactsh shows DNS or HTTP callback originating from target's IP
- IDOR: another user's private/sensitive data is visible without authorization
- RCE: command output appears in response, DNS callback triggered from target, or sleep delay confirmed
- LFI: /etc/passwd or other sensitive file content appears in response body
- Auth bypass: accessed a resource that requires authentication without providing valid credentials

NOT CONFIRMED:
- "Parameter looks injectable" — no actual exploitation evidence
- Port open / header missing — not a PoC
- Generic scanner output without demonstrated impact
- "Might be vulnerable" language

Sanitize any real passwords, PII, or credentials in safe_output — replace with [REDACTED].

Respond with valid JSON only:
{
    "confirmed": true or false,
    "evidence": "one sentence describing what specifically proves the vulnerability",
    "safe_output": "sanitized tool output or request/response safe for report inclusion",
    "request": "the HTTP request that triggered the issue (null if not available)",
    "response_snippet": "the relevant response portion showing the vulnerability (null if not available)"
}"""

    user_prompt = f"""Finding:
{json.dumps(finding_dict, default=str, indent=2)}

PoC output:
{poc_output[:5000]}

Is this confirmed?"""

    message = await client.messages.create(
        model=MODEL,
        max_tokens=800,
        temperature=0,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    )

    raw_text = ""
    try:
        raw_text = message.content[0].text if message.content else ""
        data = json.loads(_strip_json(raw_text))
    except (json.JSONDecodeError, IndexError, Exception):
        return PocResult(
            confirmed=False,
            evidence=f"Claude PoC validator returned unparseable response (len={len(raw_text)}) — manual review required",
            safe_output="",
            request=None,
            response_snippet=None,
        )

    return PocResult(
        confirmed=data["confirmed"],
        evidence=data["evidence"],
        safe_output=data["safe_output"],
        request=data.get("request"),
        response_snippet=data.get("response_snippet"),
    )


async def generate_report(finding: Finding, scope: Scope) -> str:
    """
    Generate HackerOne-ready markdown report for a confirmed finding.
    Temperature 0.5 — professional but specific.
    """
    finding_dict = finding.model_dump()
    scope_dict = scope.model_dump()

    # Parse captured HTTP evidence so Claude can embed real validation output
    evidence_block = ""
    if finding.http_evidence:
        try:
            ev = json.loads(finding.http_evidence)
            kv = ev.get("key_validation") or {}
            hf = ev.get("http_fetch") or {}
            ss = ev.get("screenshot") or {}
            parts = []
            if hf.get("status_code"):
                parts.append(f"HTTP fetch: {hf['url']} → {hf['status_code']}")
                if hf.get("context_lines"):
                    parts.append("Context from JS file:")
                    parts.extend(f"  {ln}" for ln in hf["context_lines"])
            if kv.get("curl_cmd"):
                parts.append(f"Validation command: {kv['curl_cmd']}")
            if kv.get("response_snippet"):
                parts.append(f"API validation response: {kv['response_snippet'][:400]}")
            if kv.get("status"):
                parts.append(f"Key status: {kv['status']} (validated={kv.get('validated')})")
            if ss.get("saved"):
                parts.append(f"Screenshot evidence saved: {ss.get('path')}")
            elif ss.get("error"):
                parts.append(f"Screenshot capture status: {ss.get('error')}")
            if parts:
                evidence_block = "\n\nCaptured evidence (use these exact values in the PoC section):\n" + "\n".join(parts)
        except Exception:
            pass

    vuln_type = (finding.vuln_type or "").lower()
    cors_extra = ""
    if "cors" in vuln_type:
        cors_extra = """

CORS-specific requirements (mandatory):
- Do not stop at header reflection only. Include a practical exploitation path that reads authenticated data cross-origin.
- In PoC, include:
  1) a request proving `Access-Control-Allow-Origin` reflects attacker origin,
  2) `Access-Control-Allow-Credentials: true`,
  3) a browser PoC page (`fetch(..., {credentials: \"include\"})`) that reads an authenticated endpoint response.
- If a live authenticated endpoint was not verified during scanning, clearly mark it as "requires authenticated verification" and keep claims conservative.
- Do NOT claim guaranteed account takeover unless explicit evidence exists.
- Do NOT claim attacker ownership/registration of victim subdomains unless explicitly proven by evidence.
- Use wording like "attacker-controlled origin that passes the flawed validation pattern" instead of unproven domain-control assumptions.
- Add a short subsection named "Authenticated Verification Status" stating exactly what was validated now vs what requires authenticated retest.
"""

    system_prompt = """You are an expert bug bounty reporter. Write professional, reproducible HackerOne reports.

Rules:
- Use actual URLs, parameters, and payloads from the finding data — never invent placeholders
- Output must be in English only
- CVSS: calculate accurately (AV:N/AC:L/PR:N/UI:N/S:U is typical for network-accessible vulns)
- Steps to reproduce must be 100% reproducible by a triager who has never seen this before
- PoC commands must be complete and runnable: full URLs, real headers, real payloads
- Impact must be specific to this asset and program — not generic boilerplate
- Recommended fix must be actionable and specific
- Do NOT include unconfirmed speculation
- Never leave template placeholders in output (e.g. "[add step]", "[X.X]", "[endpoint]")
- Never translate code keywords, HTTP header names, or protocol fields"""

    user_prompt = f"""Write a complete HackerOne vulnerability report for this confirmed finding.

Finding:
{json.dumps(finding_dict, default=str, indent=2)}

Program:
{json.dumps(scope_dict, indent=2)}{evidence_block}{cors_extra}

Use this exact format:

# [SEVERITY] Concise Vulnerability Title

## Summary
[1-2 paragraphs: what the vulnerability is, where it exists, and the business impact in plain language]

## Vulnerability Details
- **Asset**: [affected URL or domain]
- **Parameter / Endpoint**: [specific vulnerable parameter or endpoint]
- **CVSS Score**: [X.X (Severity label)]
- **CVSS Vector**: [CVSS:3.1/AV:.../...]
- **CWE**: [CWE-XXX: Vulnerability Name]
- **Discovered by**: [tool name]

## Steps to Reproduce
1. [Exact step — include full URL with parameters]
2. [Continue with each step]
3. [Include the exact payload used]
4. [Describe what to observe in the response]

## Proof of Concept

**One-liner (curl):**
```bash
[Complete runnable curl command that reproduces the issue — use -v for verbose, -s -o /dev/null for clean output; use the actual URL/params/headers from the finding]
```

**Python script:**
```python
import requests

# [Complete runnable Python script using requests library]
# Must print confirmation of the vulnerability to stdout
```

**Expected output:**
```
[Show exactly what the attacker sees in the response that confirms the vulnerability — actual header values, response body snippet, or status code]
```

**Raw HTTP request:**
```http
[Full HTTP request including method, path, Host header, and all relevant headers]
```

## Impact
[Specific business impact: who is affected, what attacker can do, realistic attack scenario with maximum severity. Mention affected user count or data sensitivity if known.]

## Recommended Fix
[Concrete, actionable remediation steps specific to this vulnerability type and stack. Include code examples where possible.]"""

    message = await client.messages.create(
        model=MODEL,
        max_tokens=4500,
        temperature=0.5,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    )

    report_md = message.content[0].text

    # Safety pass: remove common template leftovers / mixed-language artifacts.
    has_placeholders = bool(re.search(r"\[[^\]]*(add|step|endpoint|x\.x|severity|cwe|cvss)[^\]]*\]", report_md, re.IGNORECASE))
    has_cyrillic = bool(re.search(r"[\u0400-\u04FF]", report_md))
    if has_placeholders or has_cyrillic:
        rewrite_prompt = f"""Rewrite the following HackerOne report in clean English.

Requirements:
- Keep all factual details (URLs, headers, payloads, severity, CWE, CVSS) unchanged unless obviously invalid.
- Remove ALL placeholder/template text.
- Keep code blocks executable and do not translate code/HTTP keywords.
- Keep the same markdown structure and section headings.

Report to rewrite:
{report_md}
"""

        rewrite = await client.messages.create(
            model=MODEL,
            max_tokens=4500,
            temperature=0.2,
            system="You are a strict technical editor for bug bounty reports.",
            messages=[{"role": "user", "content": rewrite_prompt}],
        )
        report_md = rewrite.content[0].text

    return report_md


async def rewrite_report_with_quality_feedback(report_md: str, feedback: list[str]) -> str:
    """
    Rewrite report markdown using deterministic quality feedback from rule-based gate.
    """
    feedback_block = "\n".join(f"- {item}" for item in feedback)
    rewrite_prompt = f"""Revise the following HackerOne report to satisfy strict quality requirements.

Quality issues to fix:
{feedback_block}

Requirements:
- Keep all factual details unchanged unless they are clearly placeholders or unsupported claims.
- Keep output in English only.
- Keep the same top-level section structure and markdown format.
- Keep PoC snippets runnable (curl/Python/HTTP blocks).
- Do not add speculation; if evidence is missing, state that verification is required.

Report to revise:
{report_md}
"""

    rewrite = await client.messages.create(
        model=MODEL,
        max_tokens=4500,
        temperature=0.2,
        system="You are a strict technical editor for bug bounty reports.",
        messages=[{"role": "user", "content": rewrite_prompt}],
    )
    return rewrite.content[0].text if rewrite.content else report_md
