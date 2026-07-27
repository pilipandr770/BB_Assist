"""
CVSS v3.1 vector extraction + deterministic scoring.

Claude is prompted to include a CVSS vector string in every generated
report, but an LLM writing both a vector AND a matching score by hand is
exactly the kind of arithmetic a model gets subtly wrong (or just doesn't
bother to actually compute). This module extracts whatever vector string
Claude wrote and computes the score/severity from it deterministically via
the `cvss` library — the same approach usestrix/strix uses — so the number
that ends up in the report and in Report.cvss_score is always mathematically
consistent with the vector, not a free-floating guess.
"""

import re
from typing import Optional

from cvss import CVSS3
from cvss.exceptions import CVSS3MalformedError

from backend.models import Severity


_VECTOR_RE = re.compile(r"CVSS:3\.[01](?:/[A-Z]{1,3}:[A-Za-z]{1,2})+")

# Official CVSS v3.1 base-score → severity rating thresholds.
_SEVERITY_THRESHOLDS: list[tuple[float, Severity]] = [
    (9.0, Severity.critical),
    (7.0, Severity.high),
    (4.0, Severity.medium),
    (0.1, Severity.low),
]


def extract_cvss_vector(markdown: str) -> Optional[str]:
    """Find the first well-formed CVSS v3.x vector string in report markdown."""
    match = _VECTOR_RE.search(markdown)
    return match.group(0) if match else None


def severity_from_score(score: float) -> Severity:
    for threshold, severity in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return Severity.informative


def compute_cvss3(vector: str) -> Optional[tuple[float, Severity, str]]:
    """
    Compute (score, severity, normalized_vector) from a CVSS v3.x vector string.
    Returns None if the vector is missing or malformed — callers should fall
    back to whatever severity source they already had (e.g. Claude's free-text
    label) rather than failing report generation over a bad vector.
    """
    if not vector:
        return None
    try:
        c = CVSS3(vector)
        score = round(float(c.base_score), 1)
        return score, severity_from_score(score), c.clean_vector()
    except CVSS3MalformedError:
        return None
    except Exception:
        return None


def score_and_reconcile(markdown: str) -> Optional[tuple[float, Severity, str]]:
    """Extract + compute in one call. Convenience wrapper for report_generator."""
    vector = extract_cvss_vector(markdown)
    if not vector:
        return None
    return compute_cvss3(vector)
