"""Detect a program-imposed request rate limit from its policy text."""
from __future__ import annotations

import re

_PER_SECOND = re.compile(
    r"(\d{1,4})\s*(?:requests?|reqs?|req)\s*(?:/|per|a|each)\s*(?:s|sec|second)\b", re.IGNORECASE
)
_PER_MINUTE = re.compile(
    r"(\d{1,5})\s*(?:requests?|reqs?|req)\s*(?:/|per|a|each)\s*(?:m|min|minute)\b", re.IGNORECASE
)
_RATE_CONTEXT = re.compile(r"rate|limit|throttl|no more than|at most|maximum|max\b|exceed", re.IGNORECASE)


def parse_rate_limit(text: str) -> int:
    """Return the strictest requests/second stated in `text`, or 0 if none found.

    Only numbers that appear near rate-limit wording count, to avoid picking up unrelated
    statements. Per-minute limits are converted (minimum 1 req/s).
    """
    if not text:
        return 0
    found: list[int] = []
    for pattern, divisor in ((_PER_SECOND, 1), (_PER_MINUTE, 60)):
        for m in pattern.finditer(text):
            window = text[max(0, m.start() - 80): m.end() + 40]
            if not _RATE_CONTEXT.search(window):
                continue
            value = int(m.group(1))
            if value <= 0:
                continue
            found.append(max(1, value // divisor))
    return min(found) if found else 0
