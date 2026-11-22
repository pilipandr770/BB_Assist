"""Rank open HackerOne programs by how well they suit this scanner (no LLM calls).

Signals: wildcard / bounty-eligible web scope, severity ceiling, payment speed, plus penalties
for Cloudflare-fronted targets, "no automated scanning" policies and very low rate limits.
"""
from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime, timezone

from backend.services import h1_discovery
from backend.services.rate_limit import parse_rate_limit
from backend.services.waf_detect import probe_cloudflare

_NO_AUTOMATED_RE = re.compile(
    r"no\s+automated\s+scann|no\s+automated\s+(?:tools|testing)|manual\s+testing\s+only|"
    r"do\s+not\s+use\s+automated|automated\s+(?:scanning|scanners?|tools?)\s+(?:is|are)\s+(?:not\s+allowed|prohibited|forbidden)",
    re.IGNORECASE,
)
_CACHE_TTL_S = 3600
_cache: dict = {"at": 0.0, "limit": 0, "data": []}


def program_age_days(started_accepting_at: str | None, now: datetime | None = None) -> int | None:
    """Days since the program started accepting reports, or None if unknown."""
    if not started_accepting_at:
        return None
    try:
        started = datetime.fromisoformat(started_accepting_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    return max(0, ((now or datetime.now(timezone.utc)) - started).days)


def freshness_bonus(age_days: int | None) -> int:
    """Newer programs have had less time for others to find (and report) the easy bugs."""
    if age_days is None:
        return 0
    if age_days <= 30:
        return 15
    if age_days <= 90:
        return 8
    if age_days <= 180:
        return 3
    if age_days > 365:
        return -5
    return 0


def score_program(program: dict, in_scope: list[dict], policy: str, behind_cloudflare: bool) -> dict:
    web = [s for s in in_scope if s.get("type") in h1_discovery._WEB_TYPES]
    wildcards = [s for s in web if s.get("type") == "WILDCARD"]
    bounty_web = [s for s in web if s.get("bounty")]
    flags: list[str] = []
    score = 30

    score += min(len(wildcards) * 10, 30)
    score += min(len(bounty_web) * 2, 14)
    if any(str(s.get("max_severity", "")).lower() == "critical" for s in web):
        score += 5
    if program.get("fast_payments"):
        score += 5
    if program.get("gold_standard"):
        score += 3

    age_days = program_age_days(program.get("started_accepting_at"))
    bonus = freshness_bonus(age_days)
    score += bonus
    if bonus > 0:
        flags.append("new program")
    elif bonus < 0:
        flags.append("mature program (more duplicates)")

    if not web:
        score -= 15
        flags.append("no web scope")
    if behind_cloudflare:
        score -= 20
        flags.append("cloudflare")
    if _NO_AUTOMATED_RE.search(policy or ""):
        score -= 20
        flags.append("no automated scanning")
    rate = parse_rate_limit(policy or "")
    if rate and rate <= 5:
        score -= 10
        flags.append(f"rate limit {rate}/s")

    return {
        "handle": program.get("handle"),
        "name": program.get("name"),
        "score": max(0, min(100, score)),
        "wildcards": len(wildcards),
        "web_assets": len(web),
        "bounty_web_assets": len(bounty_web),
        "fast_payments": bool(program.get("fast_payments")),
        "started_accepting_at": program.get("started_accepting_at"),
        "age_days": age_days,
        "flags": flags,
        "behind_cloudflare": behind_cloudflare,
        "policy_preview": program.get("policy_preview", ""),
    }


async def rank_programs(limit: int = 30, refresh: bool = False) -> list[dict]:
    now = time.time()
    if (not refresh and _cache["data"] and _cache["limit"] >= limit
            and now - _cache["at"] < _CACHE_TTL_S):
        return _cache["data"][:limit] if _cache["limit"] == limit else _sorted(_cache["data"])[:limit]

    candidates = (await h1_discovery.list_programs(page=1, size=limit, sort="newest", refresh=refresh))["programs"]
    sem = asyncio.Semaphore(3)

    async def _one(program: dict) -> dict | None:
        async with sem:
            for attempt in range(3):  # H1 rate-limits bursts (429): back off and retry
                try:
                    in_scope, _ = await h1_discovery.get_program_scopes(program["handle"])
                    policy = await h1_discovery.get_policy_text(program["handle"])
                    domains = [
                        s["identifier"] for s in in_scope
                        if s.get("type") in ("URL", "WILDCARD") and "." in s.get("identifier", "")
                    ]
                    cf = await probe_cloudflare([d.split("//")[-1].split("/")[0] for d in domains])
                    return score_program(program, in_scope, policy, cf)
                except Exception:
                    await asyncio.sleep(1.5 * (attempt + 1))
            return None

    results = [r for r in await asyncio.gather(*(_one(p) for p in candidates)) if r]
    ranked = _sorted(results)
    _cache.update(at=now, limit=limit, data=ranked)
    return ranked


def _sorted(items: list[dict]) -> list[dict]:
    return sorted(items, key=lambda r: r["score"], reverse=True)
