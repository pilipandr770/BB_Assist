"""
HackerOne program discovery service.

Lists public bug bounty programs via the H1 REST API, filters by criteria,
and builds normalized program text for import into our scope parser.

Requires in .env:
  H1_USERNAME  — your HackerOne handle
  H1_API_TOKEN — create at https://hackerone.com/settings/api_token/edit

Notes on the H1 /hackers/programs list endpoint:
  - Returns: handle, name, offers_bounties, submission_state, open_scope,
             fast_payments, gold_standard_safe_harbor, policy (full markdown)
  - Does NOT return: bounty amounts, response times, last_report_accepted_at
    (those fields are on /v1/programs/{handle} which requires program-staff auth)
  - We therefore filter only by offers_bounties + submission_state == open
  - The `policy` markdown field is used directly as raw_text for scope parsing
"""
import logging

import httpx

from backend.config import settings

log = logging.getLogger("h1_discovery")
H1_BASE = "https://api.hackerone.com/v1"

# Asset types we care about for web/API scanning
_WEB_TYPES = {"URL", "WILDCARD", "CIDR", "IP_ADDRESS"}


def has_credentials() -> bool:
    return bool(settings.h1_username and settings.h1_api_token)


def _auth() -> tuple[str, str]:
    return (settings.h1_username or "", settings.h1_api_token or "")


async def _fetch_page(page: int, size: int) -> tuple[list, bool]:
    """Fetch one page from /hackers/programs. Returns (items, has_next)."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{H1_BASE}/hackers/programs",
            auth=_auth(),
            params={"page[number]": page, "page[size]": min(size, 100)},
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 401:
            raise ValueError("Invalid H1 credentials — check H1_USERNAME and H1_API_TOKEN in .env")
        resp.raise_for_status()
        data = resp.json()
    has_next = bool(data.get("links", {}).get("next"))
    return data.get("data", []), has_next


async def list_programs(page: int = 1, size: int = 50) -> list[dict]:
    """
    Fetch open bounty programs from HackerOne.
    Filters: offers_bounties=True AND submission_state="open".

    Note: bounty amounts are not available from this endpoint.
    The `policy_preview` field contains the first 300 chars of the program policy.
    """
    items, _ = await _fetch_page(page, size)
    results = []
    for item in items:
        attrs = item.get("attributes", {})
        if not attrs.get("offers_bounties"):
            continue
        if attrs.get("submission_state") != "open":
            continue
        results.append({
            "handle": attrs.get("handle"),
            "name": attrs.get("name"),
            "open_scope": attrs.get("open_scope", False),
            "fast_payments": attrs.get("fast_payments", False),
            "gold_standard": attrs.get("gold_standard_safe_harbor", False),
            "policy_preview": (attrs.get("policy") or "")[:300],
        })
    return results


async def get_policy_text(handle: str) -> str:
    """
    Find a program by handle in the paginated list and return its full policy text.
    Iterates up to 10 pages (×100 items = up to 1000 programs).
    """
    for page in range(1, 11):
        items, has_next = await _fetch_page(page, 100)
        for item in items:
            attrs = item.get("attributes", {})
            if attrs.get("handle") == handle:
                return attrs.get("policy") or ""
        if not has_next:
            break
    return ""


async def get_program_scopes(handle: str) -> tuple[list[dict], list[dict]]:
    """Fetch structured scopes. Returns (in_scope, out_of_scope)."""
    in_scope: list[dict] = []
    out_of_scope: list[dict] = []
    page = 1

    async with httpx.AsyncClient(timeout=30) as client:
        while True:
            resp = await client.get(
                f"{H1_BASE}/programs/{handle}/structured_scopes",
                auth=_auth(),
                params={"page[number]": page, "page[size]": 100},
                headers={"Accept": "application/json"},
            )
            if resp.status_code in (401, 403):
                # Structured scopes require program-staff auth for many programs;
                # fall back to policy text only.
                log.debug("structured_scopes %s: %s (ignored)", handle, resp.status_code)
                break
            resp.raise_for_status()
            data = resp.json()

            for item in data.get("data", []):
                attrs = item.get("attributes", {})
                entry = {
                    "type": attrs.get("asset_type", ""),
                    "identifier": attrs.get("asset_identifier", ""),
                    "bounty": attrs.get("eligible_for_bounty", False),
                    "instruction": (attrs.get("instruction") or "")[:300],
                    "max_severity": attrs.get("max_severity") or "",
                }
                if attrs.get("eligible_for_submission", True):
                    in_scope.append(entry)
                else:
                    out_of_scope.append(entry)

            if not data.get("links", {}).get("next"):
                break
            page += 1

    return in_scope, out_of_scope


def build_program_text(
    handle: str,
    name: str,
    policy_text: str,
    in_scope: list[dict],
    out_of_scope: list[dict],
) -> str:
    """
    Combine the H1 policy markdown with structured scope data.
    The policy text is used as-is (it's what H1 shows to hackers).
    Structured scopes are appended as a structured supplement.
    """
    lines: list[str] = []

    # Use existing policy text as the primary source
    if policy_text:
        lines.append(policy_text.strip())
        lines.append("")
        lines.append("---")
        lines.append("")

    lines.append(f"# Structured Scope — {name} (@{handle})")
    lines.append("")

    web_in = [s for s in in_scope if s["type"] in _WEB_TYPES]
    other_in = [s for s in in_scope if s["type"] not in _WEB_TYPES]

    if web_in:
        lines.append("## In Scope (Web/API)")
        for s in web_in:
            bounty_tag = " [bounty]" if s["bounty"] else " [no bounty]"
            sev_tag = f" [max: {s['max_severity']}]" if s["max_severity"] else ""
            lines.append(f"- {s['identifier']}{bounty_tag}{sev_tag}")
            if s["instruction"]:
                lines.append(f"  Note: {s['instruction']}")
        lines.append("")

    if other_in:
        lines.append("## In Scope (Other — not scanning targets)")
        for s in other_in:
            lines.append(f"- {s['identifier']} ({s['type']})")
        lines.append("")

    if out_of_scope:
        lines.append("## Out of Scope")
        for s in out_of_scope[:40]:
            lines.append(f"- {s['identifier']} ({s['type']})")
        lines.append("")

    return "\n".join(lines)
