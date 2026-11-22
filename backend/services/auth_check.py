"""Sanity-check user-supplied session credentials before a long authenticated scan."""
from __future__ import annotations

import httpx

_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"


def build_auth_headers(session_cookies: str = "", auth_header: str = "") -> dict[str, str]:
    headers: dict[str, str] = {}
    if session_cookies:
        headers["Cookie"] = session_cookies
    if auth_header:
        headers["Authorization"] = auth_header
    return headers


def classify_auth(authed_status: int, anon_status: int, authed_len: int, anon_len: int) -> str:
    """Return 'rejected' | 'no_effect' | 'accepted' from an authed/anonymous request pair."""
    if authed_status in (401, 403) and anon_status not in (401, 403):
        return "rejected"
    if authed_status in (401, 403):
        # Both blocked: credentials cannot be verified on this URL.
        return "no_effect"
    if authed_status == anon_status and abs(authed_len - anon_len) < max(50, int(anon_len * 0.02)):
        return "no_effect"
    return "accepted"


async def check_auth(urls: list[str], session_cookies: str, auth_header: str, max_urls: int = 4) -> dict:
    """Compare authenticated vs anonymous responses on a few live in-scope URLs."""
    headers = build_auth_headers(session_cookies, auth_header)
    if not headers or not urls:
        return {"checked": 0, "verdict": "skipped"}

    verdicts: list[str] = []
    from backend.services.tool_runner import h1_research_headers

    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False,
                                 headers={"User-Agent": _UA, **h1_research_headers()}) as client:
        for url in urls[:max_urls]:
            try:
                anon = await client.get(url)
                authed = await client.get(url, headers=headers)
            except Exception:
                continue
            verdicts.append(classify_auth(authed.status_code, anon.status_code, len(authed.content), len(anon.content)))

    if not verdicts:
        return {"checked": 0, "verdict": "unreachable"}
    if "accepted" in verdicts:
        verdict = "accepted"
    elif "rejected" in verdicts:
        verdict = "rejected"
    else:
        verdict = "no_effect"
    return {"checked": len(verdicts), "verdict": verdict}
