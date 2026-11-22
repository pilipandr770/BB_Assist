from backend.services.phases.appsec_probe_phase import is_clean_arjun_url


def test_clean_urls_pass():
    assert is_clean_arjun_url("https://www.coupang.com/np/search")
    assert is_clean_arjun_url("https://api.example.com/v1/users")


def test_malformed_urls_rejected():
    assert not is_clean_arjun_url("https://login.coupang.com/login/memberJoinFrm.pang%5C")
    assert not is_clean_arjun_url("https://example.com/api\\x")
    assert not is_clean_arjun_url("https://example.com/api/%00")
    assert not is_clean_arjun_url("https://example.com/api/привіт")
    assert not is_clean_arjun_url("ftp://example.com/api")
    assert not is_clean_arjun_url("https://example.com/api/a b")
