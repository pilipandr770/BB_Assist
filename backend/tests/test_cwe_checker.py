from backend.services.cwe_checker import check_cwe_mismatch, expected_cwe, extract_cwe


def test_extract_cwe_finds_reference():
    md = "- **CWE**: CWE-79: Cross-Site Scripting"
    assert extract_cwe(md) == 79


def test_extract_cwe_returns_none_when_absent():
    assert extract_cwe("no cwe reference here") is None


def test_expected_cwe_known_vuln_types():
    assert expected_cwe("xss") == 79
    assert expected_cwe("sqli") == 89
    assert expected_cwe("ssrf") == 918
    assert expected_cwe("cors-misconfig") == 942
    assert expected_cwe("idor") == 639


def test_expected_cwe_unmapped_vuln_type_returns_none():
    assert expected_cwe("subdomain-takeover") is None
    assert expected_cwe("") is None
    assert expected_cwe(None) is None


def test_check_cwe_mismatch_flags_wrong_cwe():
    md = "- **CWE**: CWE-79: Cross-Site Scripting"
    warning = check_cwe_mismatch(md, "sqli")
    assert warning is not None
    assert "CWE-79" in warning
    assert "CWE-89" in warning
    assert "sqli" in warning


def test_check_cwe_mismatch_passes_when_matching():
    md = "- **CWE**: CWE-89: SQL Injection"
    assert check_cwe_mismatch(md, "sqli") is None


def test_check_cwe_mismatch_silent_when_unmapped_vuln_type():
    md = "- **CWE**: CWE-79: Cross-Site Scripting"
    assert check_cwe_mismatch(md, "subdomain-takeover") is None


def test_check_cwe_mismatch_silent_when_no_cwe_written():
    assert check_cwe_mismatch("no cwe here", "xss") is None
