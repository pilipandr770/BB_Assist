"""
Scope parser — extracts and enforces program scope.

Wraps claude_service.parse_scope() and adds:
- Domain validation
- Scope enforcement check (is_in_scope)
- Known excluded vuln type lists (common across most programs)
"""

import fnmatch
import re
from urllib.parse import urlparse

from backend.models import Scope
from backend.services.claude_service import parse_scope as claude_parse_scope

_DOMAIN_RE = re.compile(
    r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|io|net|org|app|dev|co|aws|gov|edu|info|biz))\b'
)
_IGNORE_DOMAINS = {
    "hackerone.com", "disclose.io", "xss.ht", "owasp.org",
    "github.com", "cvss.org", "cve.org",
    "bugcrowd.com", "intigriti.com", "yeswehack.com", "huntr.com",
}


def _is_ignored_domain(domain: str) -> bool:
    d = domain.lower().strip().lstrip("*.")
    return any(d == base or d.endswith("." + base) for base in _IGNORE_DOMAINS)


def _infer_domains_from_text(text: str) -> list[str]:
    """Extract apex domains from raw program text as fallback when Claude finds none."""
    candidates: dict[str, int] = {}
    for m in _DOMAIN_RE.finditer(text):
        d = m.group(1).lower()
        if not _is_ignored_domain(d) and len(d) > 5:
            # Weight by frequency — the company's own domain appears most often
            candidates[d] = candidates.get(d, 0) + 1

    if not candidates:
        return []

    # Return the top-3 most-mentioned domains, add wildcard variant for the top one
    sorted_domains = sorted(candidates, key=lambda d: candidates[d], reverse=True)
    results = []
    for i, d in enumerate(sorted_domains[:3]):
        results.append(d)
        if i == 0:
            results.append(f"*.{d}")  # wildcard for the primary domain
    return results


# Vuln types excluded by the vast majority of H1 programs.
# Filtered OUT even if the program text doesn't explicitly list them.
UNIVERSALLY_EXCLUDED = [
    "missing hsts",
    "missing strict-transport-security",
    "missing csp",
    "missing content-security-policy",
    "missing x-content-type-options",
    "missing referrer-policy",
    "missing permissions-policy",
    "missing x-frame-options",
    "missing httponly",
    "missing samesite",
    "missing secure flag",
    "missing cookie flag",
    "missing email authentication",
    "missing spf",
    "missing dkim",
    "missing dmarc",
    "software version disclosure",
    "banner grabbing",
    "self xss",
    "csrf on logout",
    "csrf on unauthenticated",
    "clickjacking without sensitive action",
    "open redirect without chained impact",
    "rate limiting on non-auth",
    "tabnabbing",
    "csv injection without poc",
    "missing best practice",
    "ssl/tls configuration",
    "descriptive error message",
    "stack trace disclosure",
]


async def get_scope(raw_program_text: str) -> Scope:
    """
    Parse raw H1 program text into structured scope.
    Falls back to regex domain extraction if Claude returns no in-scope domains.
    Merges Claude-extracted scope with universally excluded types.
    """
    scope = await claude_parse_scope(raw_program_text)

    # Fallback: if Claude found no domains, infer from program text
    if not scope.in_scope_domains:
        inferred = _infer_domains_from_text(raw_program_text)
        if inferred:
            scope.in_scope_domains = inferred

    all_excluded = list(set(scope.excluded_vuln_types + UNIVERSALLY_EXCLUDED))
    scope.excluded_vuln_types = [e.lower() for e in all_excluded]
    return scope


def is_in_scope(url_or_domain: str, scope: Scope) -> bool:
    """
    Check if a URL or domain is within the program scope.
    Out-of-scope entries always take priority over in-scope.
    Supports wildcards: *.example.com matches sub.example.com and example.com.
    """
    # Extract bare domain from URL
    parsed = urlparse(url_or_domain)
    if parsed.scheme:
        domain = parsed.netloc.lower()
    else:
        domain = url_or_domain.lower()

    # Remove port number (api.example.com:8080 → api.example.com)
    if ":" in domain:
        domain = domain.split(":")[0]

    domain = domain.strip()
    if not domain:
        return False

    # Out-of-scope check takes priority
    for oos in scope.out_of_scope_domains:
        oos_clean = oos.lower().lstrip("*.")
        if domain == oos_clean or domain.endswith("." + oos_clean):
            return False

    # In-scope check with wildcard support
    for ins in scope.in_scope_domains:
        ins_lower = ins.lower().strip()
        if ins_lower.startswith("*."):
            base = ins_lower[2:]  # strip "*."
            if domain == base or domain.endswith("." + base):
                return True
        elif ins_lower == domain:
            return True
        elif fnmatch.fnmatch(domain, ins_lower):
            return True

    return False


def is_excluded_vuln_type(vuln_type: str, scope: Scope) -> bool:
    """
    Check if a vulnerability type is in the excluded list.
    Case-insensitive substring match.
    """
    vuln_lower = vuln_type.lower()
    return any(excluded in vuln_lower for excluded in scope.excluded_vuln_types)
