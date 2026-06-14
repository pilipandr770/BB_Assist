import base64
from typing import Optional

import httpx

# Map common vulnerability type strings to HackerOne weakness IDs (CWE-based).
# Keys are lowercase and may be partial matches — checked via `in` operator.
_VULN_TYPE_TO_WEAKNESS: dict[str, Optional[int]] = {
    "xss": 86,
    "cross-site-scripting": 86,
    "ssti": 86,
    "sqli": 67,
    "sql-injection": 67,
    "ssrf": 392,
    "rce": 70,
    "command-injection": 70,
    "idor": 281,
    "path-traversal": 23,
    "lfi": 23,
    "xxe": 106,
    "open-redirect": 75,
    "cors": None,
    "secret-exposure": 189,
    "api-key": 189,
    "csrf": 61,
    "subdomain-takeover": 184,
    "prototype-pollution": 1321,
}

_H1_REPORTS_URL = "https://api.hackerone.com/v1/reports"
_TIMEOUT = 30.0


def _resolve_weakness_id(vuln_type: str) -> Optional[int]:
    """Return the H1 weakness_id for a given vuln_type string, or None."""
    normalized = (vuln_type or "").strip().lower()
    for key, weakness_id in _VULN_TYPE_TO_WEAKNESS.items():
        if key in normalized:
            return weakness_id
    return None


def _build_auth_header(h1_username: str, h1_api_token: str) -> str:
    """Build the HTTP Basic Auth header value."""
    credentials = f"{h1_username}:{h1_api_token}"
    encoded = base64.b64encode(credentials.encode()).decode()
    return f"Basic {encoded}"


async def submit_report(
    report_markdown: str,
    report_title: str,
    severity: str,
    program_handle: str,
    vuln_type: str,
    h1_username: str,
    h1_api_token: str,
) -> dict:
    """Submit a vulnerability report to HackerOne via the v1 API.

    Args:
        report_markdown: Full report body in Markdown.
        report_title: Short title for the report.
        severity: One of "low", "medium", "high", "critical".
        program_handle: The H1 program slug (team_handle).
        vuln_type: Vulnerability type string used to resolve the weakness_id.
        h1_username: HackerOne account username.
        h1_api_token: HackerOne API token.

    Returns:
        dict with keys:
            success (bool)
            h1_report_id (str | None)
            h1_report_url (str | None)
            error (str | None)
    """
    weakness_id = _resolve_weakness_id(vuln_type)

    attributes: dict = {
        "team_handle": program_handle,
        "title": report_title,
        "vulnerability_information": report_markdown,
        "severity_rating": severity.lower(),
    }
    if weakness_id is not None:
        attributes["weakness_id"] = weakness_id

    payload = {
        "data": {
            "type": "report",
            "attributes": attributes,
        }
    }

    headers = {
        "Authorization": _build_auth_header(h1_username, h1_api_token),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.post(_H1_REPORTS_URL, json=payload, headers=headers)

        if response.status_code in (200, 201):
            data = response.json().get("data", {})
            report_id = str(data.get("id", ""))
            report_url = f"https://hackerone.com/reports/{report_id}" if report_id else None
            return {
                "success": True,
                "h1_report_id": report_id,
                "h1_report_url": report_url,
                "error": None,
            }

        # Non-2xx response — surface the body as an error message.
        try:
            error_body = response.json()
        except Exception:
            error_body = response.text
        return {
            "success": False,
            "h1_report_id": None,
            "h1_report_url": None,
            "error": f"H1 API returned {response.status_code}: {error_body}",
        }

    except httpx.TimeoutException:
        return {
            "success": False,
            "h1_report_id": None,
            "h1_report_url": None,
            "error": "Request to HackerOne API timed out after 30 s.",
        }
    except Exception as exc:
        return {
            "success": False,
            "h1_report_id": None,
            "h1_report_url": None,
            "error": f"Unexpected error submitting H1 report: {exc}",
        }
