"""
BB_Assist Pre-Submission Gate
==============================
Встраивается в пайплайн перед фазой генерации отчёта.
Если статус KNOWN — репорт не генерируется, находка помечается в Redis.

Использование в фазах:
    from backend.services.presubmit_gate import get_gate, GateDecision
    from backend.models import Finding

    decision = await get_gate().evaluate(finding)
    if decision.blocked:
        logger.info("Skipped duplicate: %s", finding.title)
    else:
        report = await report_generator.generate(finding, scope)
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from backend.config import settings
from backend.services.duplicate_checker import CheckStatus, DuplicateChecker

log = logging.getLogger(__name__)

REDIS_PREFIX = "bb_assist:dupcheck:"
REDIS_TTL    = 60 * 60 * 24 * 7   # 7 дней


@dataclass
class GateDecision:
    blocked:   bool
    status:    CheckStatus
    reason:    str
    h1_count:  int
    nvd_count: int
    cached:    bool = False

    def to_dict(self) -> dict:
        return {
            "blocked":    self.blocked,
            "status":     self.status.value,
            "reason":     self.reason,
            "h1_count":   self.h1_count,
            "nvd_count":  self.nvd_count,
            "cached":     self.cached,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    def warning_lines(self) -> list[str]:
        """Return warning strings to append to report when status is REVIEW."""
        if self.status != CheckStatus.REVIEW:
            return []
        return [
            f"⚠️ Duplicate check: found {self.nvd_count} NVD CVE(s) related to this "
            "vulnerability type. Verify uniqueness manually before submitting to H1.",
        ]


class PreSubmitGate:
    """
    Pre-submission gate. Evaluates a Finding against duplicate sources.

    Logic:
        KNOWN  → blocked=True  (skip report generation)
        REVIEW → blocked=False (generate report, append warning)
        UNIQUE → blocked=False (generate report normally)
    """

    def __init__(self, redis_client=None):
        self._redis   = redis_client
        self._checker = DuplicateChecker(
            timeout       = 15,
            h1_username   = settings.h1_username,
            h1_api_token  = settings.h1_api_token,
        )

    def set_redis(self, redis_client) -> None:
        self._redis = redis_client

    async def evaluate(self, finding) -> GateDecision:
        """
        Main entry point. Accepts a backend.models.Finding instance.
        Checks cache → DuplicateChecker → saves result to cache.
        """
        domain    = _extract_domain(finding.url or "")
        vuln_type = finding.vuln_type or "unknown"
        cache_key = f"{REDIS_PREFIX}{domain.replace('.', '_')}:{vuln_type}"

        # Redis cache hit
        if self._redis:
            cached = await self._cache_get(cache_key)
            if cached:
                log.debug("[Gate] cache hit: %s", cache_key)
                return GateDecision(
                    blocked   = cached["blocked"],
                    status    = CheckStatus(cached["status"]),
                    reason    = cached["reason"],
                    h1_count  = cached["h1_count"],
                    nvd_count = cached["nvd_count"],
                    cached    = True,
                )

        log.info("[Gate] checking %s / %s", domain, vuln_type)
        result = await self._checker.check(
            domain    = domain,
            vuln_type = vuln_type,
            title     = finding.title or "",
        )

        decision = GateDecision(
            blocked   = result.status == CheckStatus.KNOWN,
            status    = result.status,
            reason    = result.reason,
            h1_count  = len(result.h1_matches),
            nvd_count = len(result.nvd_matches),
        )

        if self._redis:
            await self._cache_set(cache_key, decision.to_dict())
            await self._log_decision(finding, decision)

        return decision

    # ── Redis helpers ──────────────────────────────────────────────────────

    async def _cache_get(self, key: str) -> Optional[dict]:
        try:
            raw = await self._redis.get(key)
            return json.loads(raw) if raw else None
        except Exception as exc:
            log.debug("[Gate] redis get failed: %s", exc)
            return None

    async def _cache_set(self, key: str, data: dict) -> None:
        try:
            await self._redis.setex(key, REDIS_TTL, json.dumps(data))
        except Exception as exc:
            log.debug("[Gate] redis set failed: %s", exc)

    async def _log_decision(self, finding, decision: GateDecision) -> None:
        try:
            entry = {
                "domain":    _extract_domain(finding.url or ""),
                "vuln_type": finding.vuln_type,
                "title":     finding.title,
                "severity":  finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                **decision.to_dict(),
            }
            log_key = f"{REDIS_PREFIX}history"
            await self._redis.lpush(log_key, json.dumps(entry))
            await self._redis.ltrim(log_key, 0, 499)
        except Exception as exc:
            log.debug("[Gate] redis log failed: %s", exc)


# ── Module-level singleton ─────────────────────────────────────────────────

_gate: Optional[PreSubmitGate] = None


def get_gate() -> PreSubmitGate:
    """Return the module-level gate singleton (created on first call)."""
    global _gate
    if _gate is None:
        _gate = PreSubmitGate()
    return _gate


def init_gate(redis_client) -> PreSubmitGate:
    """Call once at app startup to wire in the Redis client."""
    gate = get_gate()
    gate.set_redis(redis_client)
    return gate


# ── Helpers ───────────────────────────────────────────────────────────────

def _extract_domain(url: str) -> str:
    """Extract bare hostname from a URL string."""
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname or url
        # Strip leading wildcard / www
        return host.lstrip("*.").lower()
    except Exception:
        return url.lower()
