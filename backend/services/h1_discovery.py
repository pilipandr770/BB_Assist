"""
HackerOne program discovery service.

Lists public bug bounty programs via the H1 REST API, filters by criteria,
and builds normalized program text for import into our scope parser.

Requires in .env:
  H1_USERNAME  — your HackerOne handle
  H1_API_TOKEN — create at https://hackerone.com/settings/api_token/edit

Notes on the H1 /hackers/programs list endpoint:
  - Returns: handle, name, offers_bounties, submission_state, open_scope,
             fast_payments, gold_standard_safe_harbor, policy (full markdown),
             started_accepting_at (ISO datetime, may be null)
  - Does NOT return: bounty amounts, response times, last_report_accepted_at
    (those fields are on /v1/programs/{handle} which requires program-staff auth)
  - We filter by offers_bounties + submission_state == open
  - Seen-programs tracker (h1_seen_programs.json) enables "new since last check"
"""
import json
import logging
from pathlib import Path

import httpx

from backend.config import settings

log = logging.getLogger("h1_discovery")
H1_BASE = "https://api.hackerone.com/v1"

_WEB_TYPES = {"URL", "WILDCARD", "CIDR", "IP_ADDRESS"}


def has_credentials() -> bool:
    return bool(settings.h1_username and settings.h1_api_token)


def _auth() -> tuple[str, str]:
    return (settings.h1_username or "", settings.h1_api_token or "")


# ── seen-programs tracker ────────────────────────────────────────────────────

def _seen_file() -> Path:
    return Path(settings.workspace_dir) / "h1_seen_programs.json"


def _load_seen() -> set[str]:
    f = _seen_file()
    if f.exists():
        try:
            return set(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            pass
    return set()


def _save_seen(handles: set[str]) -> None:
    f = _seen_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(sorted(handles), indent=2), encoding="utf-8")


def mark_seen(handles: list[str]) -> None:
    """Add handles to the persistent seen set."""
    seen = _load_seen()
    seen.update(handles)
    _save_seen(seen)


# ── H1 API helpers ───────────────────────────────────────────────────────────

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


def _build_program(attrs: dict, seen: set[str]) -> dict:
    handle = attrs.get("handle") or ""
    return {
        "handle": handle,
        "name": attrs.get("name"),
        "open_scope": attrs.get("open_scope", False),
        "fast_payments": attrs.get("fast_payments", False),
        "gold_standard": attrs.get("gold_standard_safe_harbor", False),
        "policy_preview": (attrs.get("policy") or "")[:300],
        "started_accepting_at": attrs.get("started_accepting_at"),
        "is_new": handle not in seen,
    }


async def list_programs(page: int = 1, size: int = 50) -> list[dict]:
    """
    Fetch one page of open bounty programs. Marks is_new=True for handles
    not yet in the seen file.
    """
    items, _ = await _fetch_page(page, size)
    seen = _load_seen()
    results = []
    for item in items:
        attrs = item.get("attributes", {})
        if not attrs.get("offers_bounties"):
            continue
        if attrs.get("submission_state") != "open":
            continue
        results.append(_build_program(attrs, seen))
    return results


async def get_new_programs(max_pages: int = 10) -> tuple[list[dict], int]:
    """
    Scan up to max_pages×100 H1 programs and return only those not yet in the
    seen file that offer bounties and have open submissions.

    Returned list is sorted by started_accepting_at descending (newest first).
    Does NOT update the seen file — call mark_seen() explicitly when the user
    is done reviewing (e.g. "Mark all seen" button).

    Returns (new_programs, total_items_scanned).
    """
    seen = _load_seen()
    new_programs: list[dict] = []
    total_scanned = 0

    for page in range(1, max_pages + 1):
        items, has_next = await _fetch_page(page, 100)
        total_scanned += len(items)

        for item in items:
            attrs = item.get("attributes", {})
            handle = attrs.get("handle") or ""
            if not handle:
                continue
            if not attrs.get("offers_bounties"):
                continue
            if attrs.get("submission_state") != "open":
                continue
            if handle not in seen:
                new_programs.append(_build_program(attrs, seen))

        if not has_next:
            break

    new_programs.sort(
        key=lambda x: x.get("started_accepting_at") or "",
        reverse=True,
    )
    return new_programs, total_scanned


# ── program data fetchers ────────────────────────────────────────────────────

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
    Combine the H1 policy markdown with structured scope data into normalized
    text for Claude scope parsing.
    """
    lines: list[str] = []

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
