from backend.services.scan_targets import (
    build_httpx_targets,
    generate_scope_domain_urls,
    select_passive_domains,
)


def test_select_passive_domains_dedupes_by_apex():
    domains = [
        "*.shop.tw.coupang.com",
        "payment.tw.coupang.com",
        "api.tw.coupangcorp.com",
    ]
    selected = select_passive_domains(domains, max_domains=5)
    assert selected == ["shop.tw.coupang.com", "api.tw.coupangcorp.com"]


def test_select_passive_domains_respects_cap():
    domains = ["a.example.com", "b.test.com", "c.demo.net"]
    selected = select_passive_domains(domains, max_domains=2)
    assert len(selected) == 2


def test_build_httpx_targets_dedupes_preserving_order():
    targets = build_httpx_targets(
        live_hosts=["https://a.example.com"],
        nmap_endpoints=["https://a.example.com", "https://a.example.com:8443"],
        explicit_scope_urls=["https://api.example.com", "https://a.example.com:8443"],
    )
    assert targets == [
        "https://a.example.com",
        "https://a.example.com:8443",
        "https://api.example.com",
    ]


def test_generate_scope_domain_urls_includes_common_prefixes():
    generated = generate_scope_domain_urls(["*.example.com"], max_domains=1)
    assert "https://example.com" in generated
    assert "https://api.example.com" in generated
    assert "https://www.example.com" in generated
