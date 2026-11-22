from backend.services.rate_limit import parse_rate_limit


def test_per_second():
    assert parse_rate_limit("Please limit testing to a maximum of 5 requests per second.") == 5
    assert parse_rate_limit("Rate limit: 10 req/s") == 10


def test_per_minute_converted():
    assert parse_rate_limit("You must not exceed 120 requests per minute") == 2
    assert parse_rate_limit("no more than 30 requests/min") == 1


def test_strictest_wins_and_unrelated_ignored():
    assert parse_rate_limit("max 20 requests per second, but no more than 3 requests per second on login") == 3
    assert parse_rate_limit("Our site handles 5000 requests per second at peak.") == 0
    assert parse_rate_limit("") == 0
