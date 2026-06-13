import json
import os
from datetime import datetime, timezone
from typing import Any

import httpx

_CRTSH_URL = "https://crt.sh/"
_TIMEOUT = 10.0


async def fetch_ct_subdomains(domain: str) -> list[str]:
    """Query crt.sh for all subdomains of *domain* via Certificate Transparency logs.

    Args:
        domain: Apex domain, e.g. "example.com".

    Returns:
        Deduplicated, sorted list of clean subdomain strings.
        Returns an empty list if crt.sh is unreachable or returns an error.
    """
    params = {"q": f"%.{domain}", "output": "json"}

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.get(_CRTSH_URL, params=params)
        response.raise_for_status()
        entries: list[dict[str, Any]] = response.json()
    except Exception:
        # crt.sh may be slow or down — return empty rather than crashing.
        return []

    subdomains: set[str] = set()
    for entry in entries:
        name_value: str = entry.get("name_value", "")
        for name in name_value.splitlines():
            name = name.strip().lower()
            # Skip wildcards and empty strings.
            if not name or name.startswith("*"):
                continue
            subdomains.add(name)

    return sorted(subdomains)


async def check_new_subdomains(
    program_id: str,
    domains: list[str],
    workspace_dir: str,
) -> dict:
    """Compare current CT subdomains against a stored snapshot and report new ones.

    Snapshot is stored at {workspace_dir}/{program_id}/ct_snapshot.json as a JSON
    array of subdomain strings.

    Args:
        program_id: Unique program identifier used to scope the snapshot file.
        domains: List of apex domains to query (e.g. ["example.com", "api.example.com"]).
        workspace_dir: Root directory for workspace files.

    Returns:
        dict with keys:
            new_subdomains (list[str])
            total_count (int)        — total subdomains found in this run
            checked_at (str)         — ISO 8601 UTC timestamp
    """
    snapshot_dir = os.path.join(workspace_dir, program_id)
    snapshot_path = os.path.join(snapshot_dir, "ct_snapshot.json")

    # Load previous snapshot (empty set if file doesn't exist yet).
    previous: set[str] = set()
    if os.path.isfile(snapshot_path):
        try:
            with open(snapshot_path, "r", encoding="utf-8") as fh:
                previous = set(json.load(fh))
        except Exception:
            previous = set()

    # Gather subdomains from crt.sh for every supplied domain.
    current: set[str] = set()
    for domain in domains:
        found = await fetch_ct_subdomains(domain)
        current.update(found)

    new_subdomains = sorted(current - previous)
    checked_at = datetime.now(tz=timezone.utc).isoformat()

    # Persist updated snapshot.
    os.makedirs(snapshot_dir, exist_ok=True)
    try:
        with open(snapshot_path, "w", encoding="utf-8") as fh:
            json.dump(sorted(current), fh, indent=2)
    except Exception:
        # Non-fatal — we still return the results even if we couldn't save.
        pass

    return {
        "new_subdomains": new_subdomains,
        "total_count": len(current),
        "checked_at": checked_at,
    }
