from backend.models import Severity
from backend.services.cvss_calculator import (
    compute_cvss3,
    extract_cvss_vector,
    score_and_reconcile,
    severity_from_score,
)


def test_extract_cvss_vector_finds_well_formed_vector():
    md = "- **CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    assert extract_cvss_vector(md) == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"


def test_extract_cvss_vector_returns_none_when_absent():
    assert extract_cvss_vector("no vector here") is None


def test_extract_cvss_vector_returns_none_for_placeholder():
    assert extract_cvss_vector("**CVSS Vector**: [CVSS:3.1/AV:.../...]") is None


def test_severity_from_score_matches_official_thresholds():
    assert severity_from_score(9.0) == Severity.critical
    assert severity_from_score(10.0) == Severity.critical
    assert severity_from_score(8.9) == Severity.high
    assert severity_from_score(7.0) == Severity.high
    assert severity_from_score(6.9) == Severity.medium
    assert severity_from_score(4.0) == Severity.medium
    assert severity_from_score(3.9) == Severity.low
    assert severity_from_score(0.1) == Severity.low
    assert severity_from_score(0.0) == Severity.informative


def test_compute_cvss3_network_critical_vector():
    score, severity, vector = compute_cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score == 9.8
    assert severity == Severity.critical
    assert isinstance(score, float)


def test_compute_cvss3_low_impact_vector():
    score, severity, _ = compute_cvss3("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
    assert severity in (Severity.low, Severity.medium)
    assert isinstance(score, float)


def test_compute_cvss3_malformed_vector_returns_none():
    assert compute_cvss3("not a real vector") is None
    assert compute_cvss3("") is None
    assert compute_cvss3(None) is None


def test_score_and_reconcile_full_pipeline():
    md = "- **CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    result = score_and_reconcile(md)
    assert result is not None
    score, severity, vector = result
    assert severity == Severity.critical
    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"


def test_score_and_reconcile_returns_none_without_vector():
    assert score_and_reconcile("no cvss info at all") is None
