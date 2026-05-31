"""Policy/rule helpers used by scan orchestration."""

from typing import Tuple

NO_AUTOMATION_KEYWORDS = [
    "no automated scanner",
    "no automated scanning",
    "no scanners",
    "manual testing only",
    "no automated tools",
    "do not use automated",
    "do not run automated",
    "automated tools are not allowed",
    "manual testing preferred",
    "please refrain from automated",
    "refrain from automated",
    "avoid automated scanning",
    "automated testing is prohibited",
    "automated scans are prohibited",
    "do not use scanners",
    "scanner traffic is not allowed",
]


def detect_no_automation_policy(notes: str) -> Tuple[bool, list[str]]:
    """
    Return (blocked, matched_keywords) if program notes indicate scanner automation should be disabled.
    """
    haystack = (notes or "").lower()
    matches = [kw for kw in NO_AUTOMATION_KEYWORDS if kw in haystack]
    return bool(matches), matches
