# HackerOne Report Format

Claude uses this template when generating reports.
Every field must be filled with specific, confirmed information.

---

## Template

```markdown
# [Severity] Brief title describing the vulnerability and location

## Summary

One paragraph (3-5 sentences):
- What the vulnerability is (technical description)
- Where it is (specific URL/endpoint/parameter)
- What an attacker can do with it
- Why it matters to the program

Verified on: YYYY-MM-DD

## Vulnerability Details

- **Asset**: https://specific-url-here.com
- **CVSS Score**: X.X (Severity) — CVSS:3.1/AV:.../AC:...
- **CWE**: CWE-XXX (Vulnerability Type Name)

## Steps to Reproduce

1. [First step — be precise]
   ```
   curl -X POST https://target.com/api/endpoint \
        -H "Content-Type: application/json" \
        -d '{"param": "payload"}'
   ```

2. [Observe: specific response or behavior]
   ```
   HTTP/1.1 200 OK
   
   {"data": "...actual response snippet..."}
   ```

3. [Continue until impact is demonstrated]

## Proof of Concept

[Paste actual evidence here — real requests/responses, interactsh callback, etc.]

For XSS:
```
Request:  GET /search?q=<img src=x onerror=alert(document.domain)>
Response: 200 OK
          ....<img src=x onerror=alert(document.domain)>....
```

For SSRF:
```
Request:  POST /api/fetch {"url": "http://a1b2c3.oast.pro"}
Response: 200 OK {"result": "..."}
Interactsh: Received HTTP callback from {target_ip} at {timestamp}
```

For SQLi:
```
Request:  GET /api/search?id=1' AND SLEEP(5)--
Response: HTTP 200 (time: 5.2s vs normal 0.1s)
Confirms: time-based blind SQLi
```

## Impact

[Specific business impact — not generic]

An attacker can:
- [Specific action 1 — e.g., "read any user's private messages by changing user_id parameter"]
- [Specific action 2 — e.g., "execute arbitrary commands on the server"]

This affects:
- [Who is affected — all users? admin only? specific role?]
- [What data/functionality is at risk]

Real-world scenario:
[One paragraph describing a realistic attack from start to finish]

## Recommended Fix

[Specific remediation — not generic best practices]

1. [Specific fix for this exact vulnerability]
2. [Additional hardening if applicable]

[Link to relevant OWASP/documentation if helpful]
```

---

## Quality checklist before submitting

- [ ] Title is specific (not "SQL Injection found" but "Blind SQLi in /api/search id parameter allows database enumeration")
- [ ] Steps to reproduce work on first try (triager must be able to reproduce)
- [ ] PoC shows actual evidence (not "this could lead to...")
- [ ] Impact is specific (not "attacker could steal data" but "attacker can read all users' email addresses")
- [ ] CVSS vector is calculated correctly
- [ ] CWE is accurate
- [ ] Nothing in the report exceeds what was confirmed by PoC
- [ ] Vulnerability type is NOT in the program's excluded list

## Common CVSS quick reference

| Scenario | CVSS |
|---|---|
| Unauthenticated RCE | 9.8 Critical — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Auth required RCE | 8.8 High — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| SQLi, data read | 7.5 High — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| SSRF to internal | 7.5 High — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| Stored XSS | 6.1 Medium — AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| Reflected XSS | 6.1 Medium — AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| IDOR (read) | 6.5 Medium — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| Auth bypass | 9.1 Critical — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
