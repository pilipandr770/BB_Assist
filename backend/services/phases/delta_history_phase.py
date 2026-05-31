"""Helpers for delta scan history: load baseline, compare new surface, save snapshot."""

from collections.abc import Awaitable, Callable
from datetime import datetime
import json
import os

import aiofiles


EventEmitter = Callable[[str, dict], Awaitable[None]]


async def load_delta_baseline(*, delta_file: str, emit: EventEmitter) -> dict:
    prev_subdomains: set[str] = set()
    prev_live_urls: set[str] = set()
    prev_scan_date = ""

    if os.path.exists(delta_file):
        try:
            async with aiofiles.open(delta_file, encoding="utf-8") as handle:
                prev_data = json.loads(await handle.read())
            prev_subdomains = set(prev_data.get("subdomains", []))
            prev_live_urls = set(prev_data.get("live_urls", []))
            prev_scan_date = prev_data.get("scan_date", "")
            await emit(
                "delta_baseline",
                {
                    "prev_scan_date": prev_scan_date,
                    "prev_subdomains": len(prev_subdomains),
                    "prev_live_urls": len(prev_live_urls),
                },
            )
        except Exception:
            pass

    return {
        "prev_subdomains": prev_subdomains,
        "prev_live_urls": prev_live_urls,
        "prev_scan_date": prev_scan_date,
    }


async def emit_delta_new_surface(
    *,
    prev_subdomains: set[str],
    prev_live_urls: set[str],
    all_subdomains: set[str],
    live_urls: list[str],
    emit: EventEmitter,
) -> None:
    if not prev_subdomains and not prev_live_urls:
        return

    new_subdomains = sorted(all_subdomains - prev_subdomains)
    new_live_urls = sorted(set(live_urls) - prev_live_urls)
    if new_subdomains or new_live_urls:
        await emit(
            "delta_new_surface",
            {
                "new_subdomains_count": len(new_subdomains),
                "new_subdomains": new_subdomains[:20],
                "new_live_urls_count": len(new_live_urls),
                "new_live_urls": new_live_urls[:10],
            },
        )


async def save_delta_history(
    *,
    delta_file: str,
    scan_id: str,
    all_subdomains: set[str],
    live_urls: list[str],
) -> None:
    try:
        delta_data = {
            "scan_id": scan_id,
            "scan_date": datetime.utcnow().isoformat(),
            "subdomains": sorted(all_subdomains),
            "live_urls": sorted(live_urls),
        }
        async with aiofiles.open(delta_file, "w", encoding="utf-8") as handle:
            await handle.write(json.dumps(delta_data, indent=2))
    except Exception:
        pass
