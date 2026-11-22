from backend.services.auth_check import build_auth_headers, classify_auth


def test_classify():
    assert classify_auth(401, 200, 10, 5000) == "rejected"
    assert classify_auth(200, 200, 5000, 5010) == "no_effect"
    assert classify_auth(200, 302, 9000, 100) == "accepted"
    assert classify_auth(403, 403, 10, 10) == "no_effect"


def test_headers():
    assert build_auth_headers("a=1", "Bearer x") == {"Cookie": "a=1", "Authorization": "Bearer x"}
    assert build_auth_headers() == {}
