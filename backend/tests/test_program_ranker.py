from backend.services.program_ranker import score_program


def _scope(n_wild=2, n_url=3, sev="critical"):
    return (
        [{"type": "WILDCARD", "identifier": f"*.w{i}.com", "bounty": True, "max_severity": sev} for i in range(n_wild)]
        + [{"type": "URL", "identifier": f"u{i}.com", "bounty": True, "max_severity": "high"} for i in range(n_url)]
    )


def test_wide_scope_beats_cloudflare_and_no_automation():
    good = score_program({"handle": "a", "name": "A", "fast_payments": True}, _scope(), "", False)
    cf = score_program({"handle": "b", "name": "B"}, _scope(), "", True)
    manual = score_program({"handle": "c", "name": "C"}, _scope(), "Automated scanning is not allowed.", False)
    assert good["score"] > cf["score"] and good["score"] > manual["score"]
    assert "cloudflare" in cf["flags"] and "no automated scanning" in manual["flags"]


def test_no_web_scope_penalised_and_score_bounded():
    r = score_program({"handle": "d", "name": "D"}, [{"type": "ANDROID", "identifier": "x", "bounty": True}], "", False)
    assert "no web scope" in r["flags"] and 0 <= r["score"] <= 100


def test_low_rate_limit_flagged():
    r = score_program({"handle": "e", "name": "E"}, _scope(), "Rate limit: max 2 requests per second.", False)
    assert any(f.startswith("rate limit") for f in r["flags"])


def test_freshness_bonus_and_age():
    from datetime import datetime, timezone
    from backend.services.program_ranker import freshness_bonus, program_age_days

    now = datetime(2026, 11, 21, tzinfo=timezone.utc)
    assert program_age_days("2026-11-10T00:00:00.000Z", now) == 11
    assert program_age_days(None) is None and program_age_days("garbage") is None
    assert freshness_bonus(11) == 15 and freshness_bonus(60) == 8
    assert freshness_bonus(150) == 3 and freshness_bonus(250) == 0 and freshness_bonus(400) == -5


def test_new_program_outscores_identical_old_one():
    scope = [{"type": "WILDCARD", "identifier": "*.a.com", "bounty": True, "max_severity": "high"}]
    new = score_program({"handle": "n", "name": "N", "started_accepting_at": "2999-01-01T00:00:00Z"}, scope, "", False)
    old = score_program({"handle": "o", "name": "O", "started_accepting_at": "2015-01-01T00:00:00Z"}, scope, "", False)
    assert new["score"] > old["score"]
