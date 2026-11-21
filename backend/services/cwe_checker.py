"""
CWE extraction + cross-check against our own vuln_type taxonomy.

Claude is prompted to include a CWE number in every generated report, but,
like the CVSS vector before it, nothing validated it actually matched the
finding's vuln_type — a hallucinated or copy-pasted-from-a-different-template
CWE would sail through untouched. This module extracts whatever CWE number
Claude wrote and cross-checks it against a conservative, high-confidence
vuln_type -> CWE mapping.

Deliberately conservative: only vuln types with ONE well-established, widely
cited CWE are mapped (verified against common industry references — OWASP,
MITRE). Anything else returns None rather than guessing, so we never flag a
false mismatch for a vuln_type we're not actually sure about.
"""

import re
from typing import Optional

_CWE_RE = re.compile(r"CWE-(\d+)")

_VULN_TYPE_TO_CWE: dict[str, int] = {
    "xss": 79,
    "cross-site-scripting": 79,
    "sqli": 89,
    "sql-injection": 89,
    "ssrf": 918,
    "rce": 78,
    "command-injection": 78,
    "lfi": 22,
    "path-traversal": 22,
    "xxe": 611,
    "open-redirect": 601,
    "csrf": 352,
    "prototype-pollution": 1321,
    "idor": 639,
    "token-disclosure": 200,
    "secret-exposure": 200,
    "api-key": 200,
    "cors": 942,
    "cors-misconfig": 942,
}


def extract_cwe(markdown: str) -> Optional[int]:
    """Find the first CWE-NNN reference in report markdown."""
    match = _CWE_RE.search(markdown)
    return int(match.group(1)) if match else None


def expected_cwe(vuln_type: str) -> Optional[int]:
    """Return the well-established CWE for this vuln_type, or None if we
    don't have a confident single mapping for it."""
    key = (vuln_type or "").strip().lower()
    for pattern, cwe in _VULN_TYPE_TO_CWE.items():
        if pattern in key:
            return cwe
    return None


def check_cwe_mismatch(markdown: str, vuln_type: str) -> Optional[str]:
    """
    Returns a human-readable warning if the CWE Claude wrote doesn't match
    the expected one for this vuln_type, else None — either they match, or
    we have no confident expectation to check against (vuln_type unmapped,
    or no CWE line found at all; that's covered by a separate quality check).
    """
    written = extract_cwe(markdown)
    expected = expected_cwe(vuln_type)
    if written is None or expected is None:
        return None
    if written != expected:
        return (
            f"Report states CWE-{written}, but vuln_type '{vuln_type}' is "
            f"normally classified as CWE-{expected} — verify before submitting."
        )
    return None
