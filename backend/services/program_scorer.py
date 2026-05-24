import asyncio
import json
import re

import anthropic

from backend.config import settings

MODEL = "claude-sonnet-4-6"
_client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)

_NO_AUTOMATED_RE = re.compile(
    r"no\s+automated\s+scanner|no\s+automated\s+scanning|manual\s+testing\s+only|do\s+not\s+use\s+automated",
    re.IGNORECASE,
)

_OUR_TYPES = {"xss", "sqli", "ssrf", "idor", "cors", "subdomain_takeover"}


def _strip_json(text: str) -> str:
    t = (text or "").strip()
    if t.startswith("```"):
        lines = t.split("\n")
        inner = lines[1:-1] if lines and lines[-1].strip() == "```" else lines[1:]
        t = "\n".join(inner).strip()
    start = t.find("{")
    end = t.rfind("}")
    if start != -1 and end != -1 and end > start:
        return t[start : end + 1]
    return t


def _normalize_result(data: dict) -> dict:
    return {
        "program_name": data.get("program_name", "Unknown Program"),
        "score": int(data.get("score", 0)),
        "scope_type": str(data.get("scope_type", "mixed")).lower(),
        "wildcard_domains": bool(data.get("wildcard_domains", False)),
        "automated_scanner_allowed": bool(data.get("automated_scanner_allowed", False)),
        "excluded_vuln_types": list(data.get("excluded_vuln_types", [])),
        "our_tool_fit": list(data.get("our_tool_fit", [])),
        "missing_coverage": list(data.get("missing_coverage", [])),
        "top_targets": list(data.get("top_targets", [])),
        "recommendation": str(data.get("recommendation", "")),
        "red_flags": list(data.get("red_flags", [])),
    }


def _apply_score_formula(program_text: str, result: dict) -> int:
    score = 50

    if result.get("wildcard_domains"):
        score += 20

    if result.get("automated_scanner_allowed"):
        score += 15

    if _NO_AUTOMATED_RE.search(program_text or ""):
        score -= 20

    scope_type = (result.get("scope_type") or "").lower()
    if scope_type in ("web", "api"):
        score += 10
    if scope_type == "mobile":
        score -= 15
    if scope_type == "blockchain":
        score -= 20

    fit = [str(v).strip().lower() for v in (result.get("our_tool_fit") or [])]
    matched = len([v for v in fit if v in _OUR_TYPES])
    score += min(matched * 5, 15)

    red_flags = result.get("red_flags") or []
    score -= min(len(red_flags) * 5, 20)

    return max(0, min(100, score))


async def score_program(program_text: str) -> dict:
    prompt = f"""You are a senior bug bounty triager.
Analyze this HackerOne program scope text and return ONLY valid JSON with this exact schema:
{{
  "program_name": "...",
  "score": 0,
  "scope_type": "web|api|mobile|blockchain|mixed",
  "wildcard_domains": true,
  "automated_scanner_allowed": true,
  "excluded_vuln_types": ["..."],
  "our_tool_fit": ["XSS", "SQLi", "SSRF", "CORS", "subdomain_takeover"],
  "missing_coverage": ["mobile", "..."],
  "top_targets": ["*.example.com", "api.example.com"],
  "recommendation": "short 1-2 sentence reason for this score",
  "red_flags": ["no automated testing", "very narrow scope"]
}}

Guidelines:
- Determine if wildcard domains exist.
- Determine if automated scanners are allowed.
- Extract excluded vulnerability classes.
- Keep recommendation concise.
- Return JSON only, no markdown.

Program text:
{program_text}
"""

    msg = await _client.messages.create(
        model=MODEL,
        max_tokens=1800,
        temperature=0,
        messages=[{"role": "user", "content": prompt}],
    )
    raw = msg.content[0].text if msg.content else "{}"

    try:
        data = json.loads(_strip_json(raw))
    except Exception:
        data = {
            "program_name": "Unknown Program",
            "scope_type": "mixed",
            "wildcard_domains": bool(re.search(r"\*\.[a-z0-9.-]+", program_text, re.IGNORECASE)),
            "automated_scanner_allowed": not bool(_NO_AUTOMATED_RE.search(program_text or "")),
            "excluded_vuln_types": [],
            "our_tool_fit": [],
            "missing_coverage": [],
            "top_targets": [],
            "recommendation": "Could not fully parse scope with AI response; scored conservatively.",
            "red_flags": ["ai_parse_failed"],
        }

    normalized = _normalize_result(data)
    normalized["score"] = _apply_score_formula(program_text, normalized)
    normalized["program_text"] = program_text
    return normalized


async def score_multiple(programs: list[str]) -> list[dict]:
    results = await asyncio.gather(*(score_program(p) for p in programs))
    return sorted(results, key=lambda x: x.get("score", 0), reverse=True)
