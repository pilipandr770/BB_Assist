from backend.services.waf_detect import detect_waf_profile


def test_all_cloudflare_is_heavy():
    results = [
        {"url": "https://a.example.com", "webserver": "cloudflare"},
        {"url": "https://b.example.com", "header": {"Cf-Ray": "123"}},
        {"url": "https://c.example.com", "tech": ["Cloudflare", "HSTS"]},
    ]
    p = detect_waf_profile(results)
    assert p.total_hosts == 3 and p.cloudflare_hosts == 3
    assert p.cloudflare_heavy


def test_mixed_below_threshold_not_heavy():
    results = [
        {"url": "https://a.example.com", "webserver": "cloudflare"},
        {"url": "https://b.example.com", "webserver": "nginx"},
        {"url": "https://c.example.com", "webserver": "Apache"},
    ]
    p = detect_waf_profile(results)
    assert p.cloudflare_hosts == 1
    assert not p.cloudflare_heavy


def test_duplicate_results_per_host_counted_once():
    results = [
        {"url": "https://a.example.com/x", "host": "a.example.com", "webserver": "cloudflare"},
        {"url": "https://a.example.com/y", "host": "a.example.com", "webserver": "nginx"},
    ]
    p = detect_waf_profile(results)
    assert p.total_hosts == 1 and p.cloudflare_hosts == 1


def test_empty_results():
    p = detect_waf_profile([])
    assert p.total_hosts == 0 and not p.cloudflare_heavy


def test_origin_candidates_exclude_cloudflare_and_private():
    from backend.services.waf_detect import select_origin_candidates, is_cloudflare_ip

    assert is_cloudflare_ip("104.18.2.3") and not is_cloudflare_ip("8.8.8.8")
    out = select_origin_candidates({
        "www.example.com": ["104.18.2.3"],
        "mail.example.com": ["93.184.216.34"],
        "intranet.example.com": ["10.0.0.5"],
        "mixed.example.com": ["104.18.2.3", "93.184.216.35"],
    })
    assert out == {"mail.example.com": ["93.184.216.34"]}


def test_resolver_unreliable_when_cf_host_resolves_outside_cf():
    from backend.services.waf_detect import resolver_looks_unreliable

    assert resolver_looks_unreliable({"a.example.com": ["194.67.193.1"]}, {"a.example.com"})
    assert not resolver_looks_unreliable({"a.example.com": ["104.18.2.3"]}, {"a.example.com"})
    assert not resolver_looks_unreliable({}, {"a.example.com"})
