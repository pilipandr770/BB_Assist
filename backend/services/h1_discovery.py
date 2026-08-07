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
  - ORDERING: results always come back by internal program id ASCENDING, i.e.
    oldest programs first (page 1 is the 2013 cohort). A `sort` query param is
    accepted but silently ignored by the API. So the only way to show the
    newest programs is to pull the whole catalogue (~600 programs / 6 pages)
    and order it locally — that is what _fetch_all() + _sorted() do, behind a
    TTL cache so the ~15 s full fetch happens once per CACHE_TTL.
  - We filter by offers_bounties + submission_state == open
  - Seen-programs tracker (h1_seen_programs.json) enables "new since last check"
"""
import asyncio
import json
import logging
import time
from pathlib import Path

import httpx

from backend.config import settings

log = logging.getLogger("h1_discovery")
H1_BASE = "https://api.hackerone.com/v1"

_WEB_TYPES = {"URL", "WILDCARD", "CIDR", "IP_ADDRESS"}

# Full-catalogue fetch tuning. H1 caps page[size] at 100; out-of-range pages
# return 200 with an empty data array, so over-requesting a batch is safe.
_PAGE_SIZE = 100
_PARALLEL_PAGES = 6
_MAX_PAGES = 60

CACHE_TTL = 900.0  # seconds — full catalogue is re-fetched at most every 15 min


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

async def _fetch_page(client: httpx.AsyncClient, page: int) -> tuple[list, bool]:
    """Fetch one page from /hackers/programs. Returns (items, has_next)."""
    resp = await client.get(
        f"{H1_BASE}/hackers/programs",
        auth=_auth(),
        params={"page[number]": page, "page[size]": _PAGE_SIZE},
        headers={"Accept": "application/json"},
    )
    if resp.status_code == 401:
        raise ValueError("Invalid H1 credentials — check H1_USERNAME and H1_API_TOKEN in .env")
    resp.raise_for_status()
    data = resp.json()
    return data.get("data", []), bool(data.get("links", {}).get("next"))


async def _fetch_all() -> list[dict]:
    """
    Fetch every page of /hackers/programs, in parallel batches.

    The API gives no total count, so we request _PARALLEL_PAGES at a time and
    stop once the last page of a batch reports no `next` link.
    """
    items: list[dict] = []
    async with httpx.AsyncClient(timeout=60) as client:
        page = 1
        while page <= _MAX_PAGES:
            batch = range(page, page + _PARALLEL_PAGES)
            results = await asyncio.gather(*(_fetch_page(client, p) for p in batch))
            for page_items, _ in results:
                items.extend(page_items)
            if not results[-1][1]:
                break
            page += _PARALLEL_PAGES
        else:
            log.warning("H1 catalogue hit the %d-page cap — results may be truncated", _MAX_PAGES)
    return items


# ── full-catalogue cache ─────────────────────────────────────────────────────

_cache: dict = {"at": 0.0, "raw": []}
_cache_lock = asyncio.Lock()


async def _catalogue(refresh: bool = False) -> list[dict]:
    """
    Return every raw program item, from cache when fresh. The lock keeps
    concurrent requests from each triggering their own full fetch.
    """
    async with _cache_lock:
        fresh = _cache["raw"] and (time.monotonic() - _cache["at"]) < CACHE_TTL
        if fresh and not refresh:
            return _cache["raw"]
        t0 = time.monotonic()
        raw = await _fetch_all()
        log.info("Fetched %d H1 programs in %.1fs", len(raw), time.monotonic() - t0)
        _cache["raw"] = raw
        _cache["at"] = time.monotonic()
        return raw


def _build_program(item: dict, seen: set[str]) -> dict:
    attrs = item.get("attributes", {})
    handle = attrs.get("handle") or ""
    return {
        "id": item.get("id"),
        "handle": handle,
        "name": attrs.get("name"),
        "open_scope": attrs.get("open_scope", False),
        "fast_payments": attrs.get("fast_payments", False),
        "gold_standard": attrs.get("gold_standard_safe_harbor", False),
        "policy_preview": (attrs.get("policy") or "")[:300],
        "started_accepting_at": attrs.get("started_accepting_at"),
        "is_new": handle not in seen,
    }


def _sort_programs(programs: list[dict], sort: str) -> list[dict]:
    """
    Return a newly ordered list. Supported keys:
      newest  — most recently launched first (started_accepting_at desc)
      oldest  — started_accepting_at asc
      added   — most recently added to H1 first (internal id desc)
      name    — alphabetical

    started_accepting_at comes back as a uniform UTC ISO string, so plain
    string comparison orders it correctly. Programs missing the date sort last,
    with the internal id as tiebreaker so they still land sensibly.
    """
    def _id(p: dict) -> int:
        try:
            return int(p.get("id") or 0)
        except (TypeError, ValueError):
            return 0

    if sort == "added":
        return sorted(programs, key=_id, reverse=True)
    if sort == "name":
        return sorted(programs, key=lambda p: (p.get("name") or p["handle"]).lower())
    if sort == "oldest":
        return sorted(programs, key=lambda p: (p.get("started_accepting_at") or "9999", _id(p)))
    # newest (default)
    return sorted(
        programs,
        key=lambda p: (p.get("started_accepting_at") or "", _id(p)),
        reverse=True,
    )


async def _open_bounty_programs(refresh: bool = False) -> list[dict]:
    """All programs that offer bounties and are open for submissions."""
    raw = await _catalogue(refresh=refresh)
    seen = _load_seen()
    out: list[dict] = []
    for item in raw:
        attrs = item.get("attributes", {})
        if not attrs.get("handle"):
            continue
        if not attrs.get("offers_bounties"):
            continue
        if attrs.get("submission_state") != "open":
            continue
        out.append(_build_program(item, seen))
    return out


async def list_programs(
    page: int = 1,
    size: int = 50,
    sort: str = "newest",
    refresh: bool = False,
) -> dict:
    """
    Return one page of open bounty programs, sorted as requested.

    Pagination is done locally over the cached catalogue — the H1 API only
    serves oldest-first pages, so slicing its pages directly would never
    surface recent programs.

    Returns {programs, total, page, size, has_more}.
    """
    programs = _sort_programs(await _open_bounty_programs(refresh=refresh), sort)
    start = (page - 1) * size
    window = programs[start:start + size]
    return {
        "programs": window,
        "total": len(programs),
        "page": page,
        "size": size,
        "has_more": start + size < len(programs),
    }


async def get_new_programs(refresh: bool = False) -> tuple[list[dict], int]:
    """
    Return open bounty programs not yet in the seen file, newest first.

    Does NOT update the seen file — call mark_seen() explicitly when the user
    is done reviewing (e.g. "Mark all seen" button).

    Returns (new_programs, total_programs_scanned).
    """
    raw = await _catalogue(refresh=refresh)
    programs = await _open_bounty_programs()
    new_programs = [p for p in programs if p["is_new"]]
    return _sort_programs(new_programs, "newest"), len(raw)


# ── program data fetchers ────────────────────────────────────────────────────

async def get_policy_text(handle: str) -> str:
    """Return a program's full policy markdown, looked up in the cached catalogue."""
    for item in await _catalogue():
        if item.get("attributes", {}).get("handle") == handle:
            return item["attributes"].get("policy") or ""
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
