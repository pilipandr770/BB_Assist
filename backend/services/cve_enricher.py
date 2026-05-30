"""
CVE enricher — adds EPSS and CISA KEV data to findings that reference CVE IDs.

EPSS  (Exploit Prediction Scoring System):
  - Score 0–1: probability of exploitation in the next 30 days
  - Percentile 0–1: rank among all scored CVEs
  - Free API, no key required, 1000 req/min

CISA KEV (Known Exploited Vulnerabilities catalog):
  - Binary: is this CVE actively exploited in the wild right now?
  - Free static JSON, updated on US business days
  - Cached in memory for 1 hour to avoid hammering CISA's CDN

Both signals are included in Claude's finding context so the AI can:
  - Raise severity for high-EPSS / KEV findings
  - Write "actively exploited in the wild" in HackerOne reports
  - Add EPSS percentile as evidence of exploitability
"""

import asyncio
import json
import logging
import re
import time
from typing import Optional

import httpx as _httpx

log = logging.getLogger("cve_enricher")

# ── In-memory cache for CISA KEV (refreshed every hour) ───────────────────────
_kev_cache: set[str] = set()          # set of CVE IDs that are in KEV
_kev_fetched_at: float = 0.0          # epoch seconds of last successful fetch
_KEV_TTL = 3600                       # 1 hour
_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# ── EPSS API ───────────────────────────────────────────────────────────────────
_EPSS_URL = "https://api.first.org/data/v1/epss"
_EPSS_TTL = 21600                     # 6 hours — EPSS updates daily

# Simple per-CVE EPSS cache: {"CVE-xxxx": {"score": 0.9, "percentile": 0.99, "ts": epoch}}
_epss_cache: dict[str, dict] = {}

# ── CVE ID extraction regex ────────────────────────────────────────────────────
_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)


def extract_cve_ids(text: str) -> list[str]:
    """Extract all unique CVE IDs from arbitrary text (nuclei output, titles, etc.)."""
    return list({m.upper() for m in _CVE_RE.findall(text)})


# ── CISA KEV ───────────────────────────────────────────────────────────────────

async def _refresh_kev_if_stale() -> None:
    """Fetch KEV catalog from CISA if cache is older than TTL."""
    global _kev_cache, _kev_fetched_at
    now = time.monotonic()
    if now - _kev_fetched_at < _KEV_TTL:
        return  # still fresh

    try:
        async with _httpx.AsyncClient(timeout=20, verify=True) as client:
            resp = await client.get(_KEV_URL)
            resp.raise_for_status()
            data = resp.json()
        cves = {v["cveID"].upper() for v in data.get("vulnerabilities", []) if v.get("cveID")}
        _kev_cache = cves
        _kev_fetched_at = now
        log.info("cve_enricher: KEV catalog refreshed — %d CVEs", len(cves))
    except Exception as exc:
        # Don't crash the pipeline — KEV enrichment is optional
        log.warning("cve_enricher: KEV fetch failed: %s", exc)


async def is_in_kev(cve_id: str) -> bool:
    """Return True if the CVE is in CISA's Known Exploited Vulnerabilities catalog."""
    await _refresh_kev_if_stale()
    return cve_id.upper() in _kev_cache


# ── EPSS ───────────────────────────────────────────────────────────────────────

async def get_epss(cve_ids: list[str]) -> dict[str, dict]:
    """
    Fetch EPSS scores for a list of CVE IDs.
    Returns dict: {cve_id: {"score": float, "percentile": float, "date": str}}
    Uses in-process cache with 6-hour TTL.
    Batches up to 100 CVEs per request (API limit).
    """
    if not cve_ids:
        return {}

    now = time.monotonic()
    result: dict[str, dict] = {}
    to_fetch: list[str] = []

    for cve in cve_ids:
        cached = _epss_cache.get(cve.upper())
        if cached and (now - cached.get("ts", 0)) < _EPSS_TTL:
            result[cve.upper()] = cached
        else:
            to_fetch.append(cve.upper())

    if to_fetch:
        # EPSS API accepts comma-separated CVE IDs, max ~100 at once
        for batch_start in range(0, len(to_fetch), 100):
            batch = to_fetch[batch_start:batch_start + 100]
            params = {"cve": ",".join(batch)}
            try:
                async with _httpx.AsyncClient(timeout=15, verify=True) as client:
                    resp = await client.get(_EPSS_URL, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                for item in data.get("data", []):
                    cve_id = item.get("cve", "").upper()
                    entry = {
                        "score": float(item.get("epss", 0)),
                        "percentile": float(item.get("percentile", 0)),
                        "date": item.get("date", ""),
                        "ts": now,
                    }
                    _epss_cache[cve_id] = entry
                    result[cve_id] = entry
            except Exception as exc:
                log.warning("cve_enricher: EPSS fetch failed for batch %s: %s", batch[:3], exc)

    return result


# ── Main enrichment entry point ─────────────────────────────────────────────────

async def enrich_finding(raw_output: str, title: str = "", tool: str = "") -> dict:
    """
    Extract CVE IDs from finding output and enrich with EPSS + KEV data.

    Returns a dict suitable for injection into Claude's prompt:
    {
      "cves_found": ["CVE-2024-3400"],
      "epss": {"CVE-2024-3400": {"score": 0.97, "percentile": 0.999}},
      "kev": {"CVE-2024-3400": true},
      "summary": "CVE-2024-3400: EPSS 97.0% (top 0.1%), ACTIVELY EXPLOITED (CISA KEV)"
    }
    Returns empty dict {} if no CVEs found (no overhead for non-CVE findings).
    """
    search_text = f"{title} {raw_output} {tool}"
    cve_ids = extract_cve_ids(search_text)
    if not cve_ids:
        return {}

    # Run EPSS and KEV lookups concurrently
    epss_data, kev_results_list = await asyncio.gather(
        get_epss(cve_ids),
        asyncio.gather(*[is_in_kev(c) for c in cve_ids]),
        return_exceptions=False,
    )
    kev_map = {cve.upper(): in_kev for cve, in_kev in zip(cve_ids, kev_results_list)}

    # Build human-readable summary for Claude's context
    lines = []
    for cve in sorted(cve_ids):
        parts = [cve]
        epss = epss_data.get(cve, {})
        if epss:
            score_pct = epss["score"] * 100
            percentile_pct = epss["percentile"] * 100
            parts.append(f"EPSS {score_pct:.1f}% (top {100 - percentile_pct:.1f}%ile)")
        if kev_map.get(cve):
            parts.append("⚠ ACTIVELY EXPLOITED — CISA KEV")
        lines.append(": ".join(parts))

    return {
        "cves_found": cve_ids,
        "epss": {k: {kk: vv for kk, vv in v.items() if kk != "ts"} for k, v in epss_data.items()},
        "kev": kev_map,
        "summary": "\n".join(lines) if lines else "",
    }


def severity_boost(enrichment: dict) -> Optional[str]:
    """
    Suggest a severity upgrade based on EPSS + KEV signals.
    Returns "critical" | "high" | None — caller decides whether to apply.

    Rules:
      - Any CVE in CISA KEV → at minimum "high" (likely critical if CVSS is high)
      - EPSS ≥ 0.50 (top 50% probability of exploitation) → "high"
      - EPSS ≥ 0.90 + KEV → "critical"
    """
    if not enrichment:
        return None

    kev_map = enrichment.get("kev", {})
    epss_map = enrichment.get("epss", {})

    any_kev = any(kev_map.values())
    max_epss = max((v.get("score", 0) for v in epss_map.values()), default=0.0)

    if any_kev and max_epss >= 0.90:
        return "critical"
    if any_kev:
        return "high"
    if max_epss >= 0.50:
        return "high"
    return None
