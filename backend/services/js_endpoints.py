"""Extract API endpoints from downloaded JavaScript (single pass, no extra requests)."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

# Relative API-looking paths inside string literals: "/api/v1/users", '/graphql', `/v2/orders`
_REL_RE = re.compile(
    r"""["'`](/(?:api|v\d{1,2}|graphql|rest|internal|private|admin|auth|oauth2?|sso|login|"""
    r"""user|users|account|accounts|payment|payments|order|orders|checkout|upload|download|"""
    r"""export|import|webhook|callback|token|session|search|query)(?:/[A-Za-z0-9_\-.~%]*)*)["'`]""",
    re.IGNORECASE,
)
# Absolute URLs in string literals
_ABS_RE = re.compile(r"""["'`](https?://[A-Za-z0-9.\-]+(?::\d+)?(?:/[A-Za-z0-9_\-./~%]*)?)["'`]""")

_STATIC_SUFFIXES = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webp",
)
MAX_PER_FILE = 100


def extract_js_endpoints(content: str, js_url: str) -> list[str]:
    """Return absolute endpoint URLs found in `content`, resolved against js_url's origin."""
    parsed = urlparse(js_url)
    if not parsed.scheme or not parsed.netloc:
        return []
    origin = f"{parsed.scheme}://{parsed.netloc}"

    found: list[str] = []
    for m in _REL_RE.finditer(content):
        found.append(urljoin(origin, m.group(1)))
    for m in _ABS_RE.finditer(content):
        found.append(m.group(1))

    out: list[str] = []
    seen: set[str] = set()
    for url in found:
        if "{" in url or "$" in url or url in seen:
            continue
        path = urlparse(url).path.lower()
        if path.endswith(_STATIC_SUFFIXES):
            continue
        # A bare origin carries no information beyond what recon already has.
        if path in ("", "/"):
            continue
        seen.add(url)
        out.append(url)
        if len(out) >= MAX_PER_FILE:
            break
    return out
