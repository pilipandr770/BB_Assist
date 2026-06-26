"""
Duplicate / known-issue checker for BB_Assist pre-submission gate.

Three signal sources (fastest to slowest):
  1. Local SQLite  — own previous scans (domain + vuln_type already found)
  2. H1 Hacktivity — public disclosed reports (requires H1 credentials)
  3. NVD REST API  — CVE keyword presence (no auth needed)

CheckStatus:
  KNOWN  → blocked (local DB hit OR H1 Hacktivity hit)
  REVIEW → pass with warning (NVD CVE hit only)
  UNIQUE → pass, no matches found
"""

import enum
import logging
from dataclasses import dataclass, field
from urllib.parse import urlencode

import httpx

log = logging.getLogger(__name__)

# ── Vulnerability keyword mapping ──────────────────────────────────────────
# Keys are canonical vuln_type strings (used in Finding.vuln_type).
# Values: (primary NVD keyword, *aliases for H1 text search)
VULN_KEYWORDS: dict[str, tuple[str, ...]] = {
    "xss":                ("cross-site scripting", "xss", "reflected xss", "stored xss"),
    "sqli":               ("sql injection", "sqli", "blind sql"),
    "ssrf":               ("server-side request forgery", "ssrf"),
    "rce":                ("remote code execution", "rce", "command injection"),
    "idor":               ("insecure direct object reference", "idor"),
    "open-redirect":      ("open redirect",),
    "token-disclosure":   ("api key exposure", "exposed secret", "token disclosure", "hardcoded credential"),
    "subdomain-takeover": ("subdomain takeover",),
    "cors":               ("cors misconfiguration", "cors"),
    "lfi":                ("local file inclusion", "lfi", "path traversal"),
    "xxe":                ("xml external entity", "xxe"),
    "csrf":               ("cross-site request forgery", "csrf"),
    "ssti":               ("server-side template injection", "ssti"),
    "prototype-pollution":("prototype pollution",),
    "auth-bypass":        ("authentication bypass", "auth bypass"),
}

_H1_HACKTIVITY = "https://api.hackerone.com/v1/hackers/hacktivity"
_NVD_CPE_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CheckStatus(enum.Enum):
    UNIQUE = "UNIQUE"
    REVIEW = "REVIEW"
    KNOWN  = "KNOWN"


@dataclass
class CheckResult:
    status:      CheckStatus
    reason:      str
    h1_matches:  list = field(default_factory=list)
    nvd_matches: list = field(default_factory=list)


class DuplicateChecker:
    def __init__(
        self,
        timeout: int = 15,
        h1_username: str | None = None,
        h1_api_token: str | None = None,
    ):
        self.timeout       = timeout
        self.h1_username   = h1_username
        self.h1_api_token  = h1_api_token

    async def check(self, domain: str, vuln_type: str, title: str) -> CheckResult:
        """
        Run all three checks. Returns the strictest matching status.
        """
        # 1 — Local DB (fastest, most reliable for our own past reports)
        local_hit = await self._check_local_db(domain, vuln_type)
        if local_hit:
            return CheckResult(
                status=CheckStatus.KNOWN,
                reason=f"Already reported: same domain+vuln_type found in local scan history ({local_hit})",
                h1_matches=[local_hit],
            )

        # 2 — H1 Hacktivity (requires credentials)
        h1_matches = await self._check_h1_hacktivity(domain, vuln_type, title)
        if h1_matches:
            return CheckResult(
                status=CheckStatus.KNOWN,
                reason=f"Found {len(h1_matches)} similar disclosed H1 report(s) for this domain/vuln_type",
                h1_matches=h1_matches,
            )

        # 3 — NVD (informational — raises to REVIEW, never KNOWN)
        nvd_matches = await self._check_nvd(vuln_type)
        if nvd_matches:
            return CheckResult(
                status=CheckStatus.REVIEW,
                reason=f"Found {len(nvd_matches)} NVD CVE(s) related to '{vuln_type}' — verify before submitting",
                nvd_matches=nvd_matches,
            )

        return CheckResult(
            status=CheckStatus.UNIQUE,
            reason="No duplicates found in local DB, H1 Hacktivity, or NVD",
        )

    # ── Source 1: Local SQLite ──────────────────────────────────────────────

    async def _check_local_db(self, domain: str, vuln_type: str) -> str | None:
        """
        Return a descriptive string if we already have a passing finding
        for the same (domain, vuln_type) in a previous scan, else None.
        """
        try:
            import aiosqlite
            from backend.config import settings
            import os

            db_path = os.path.join(settings.workspace_dir, "bb_assist.db")
            async with aiosqlite.connect(db_path) as db:
                async with db.execute(
                    """
                    SELECT f.title, f.target, s.program_id, f.created_at
                    FROM findings f
                    JOIN scans s ON s.id = f.scan_id
                    WHERE f.passed_filter = 1
                      AND LOWER(f.vuln_type) = LOWER(?)
                      AND LOWER(f.target) LIKE ?
                    ORDER BY f.created_at DESC
                    LIMIT 1
                    """,
                    (vuln_type, f"%{domain.lower()}%"),
                ) as cur:
                    row = await cur.fetchone()
                    if row:
                        return f'"{row[0]}" on {row[1]} (scan {row[2]}, {row[3][:10]})'
        except Exception as exc:
            log.debug("Local DB duplicate check failed: %s", exc)
        return None

    # ── Source 2: H1 Hacktivity ─────────────────────────────────────────────

    async def _check_h1_hacktivity(
        self, domain: str, vuln_type: str, title: str
    ) -> list[dict]:
        if not (self.h1_username and self.h1_api_token):
            return []

        keywords = VULN_KEYWORDS.get(vuln_type.lower(), (vuln_type,))
        query    = f"{domain} {keywords[0]}"

        params = {
            "filter[text_query]":           query,
            "filter[report][disclosed]":    "true",
            "page[size]":                   "5",
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    _H1_HACKTIVITY,
                    params=params,
                    auth=(self.h1_username, self.h1_api_token),
                    headers={"Accept": "application/json"},
                )
                if resp.status_code != 200:
                    log.debug("H1 Hacktivity returned %d", resp.status_code)
                    return []
                data  = resp.json()
                items = data.get("data", [])
                return [
                    {
                        "id":    item.get("id"),
                        "title": item.get("attributes", {}).get("title", ""),
                        "url":   item.get("attributes", {}).get("url", ""),
                    }
                    for item in items
                ]
        except Exception as exc:
            log.debug("H1 Hacktivity check failed: %s", exc)
            return []

    # ── Source 3: NVD REST API ──────────────────────────────────────────────

    async def _check_nvd(self, vuln_type: str) -> list[dict]:
        keywords = VULN_KEYWORDS.get(vuln_type.lower(), ())
        if not keywords:
            return []

        keyword = keywords[0]
        params  = {"keywordSearch": keyword, "resultsPerPage": "3"}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    _NVD_CPE_URL,
                    params=params,
                    headers={"Accept": "application/json"},
                )
                if resp.status_code != 200:
                    return []
                items = resp.json().get("vulnerabilities", [])
                return [
                    {
                        "cve_id":      item["cve"]["id"],
                        "description": (
                            item["cve"]
                            .get("descriptions", [{}])[0]
                            .get("value", "")[:120]
                        ),
                    }
                    for item in items
                ]
        except Exception as exc:
            log.debug("NVD check failed: %s", exc)
            return []
