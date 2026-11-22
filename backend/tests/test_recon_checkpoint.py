import os
import tempfile

from backend.services.phases.web_pipeline_phase import _load_recon_checkpoint, _save_recon_checkpoint


def _sample():
    return {
        "all_subdomains": {"a.example.com", "b.example.com"},
        "live_hosts": ["a.example.com"],
        "nmap_endpoints": [],
        "nmap_service_versions": [{"host": "a.example.com", "port": 443}],
        "nmap_csv_cve_hits": [],
        "shodan_vuln_findings": [],
        "live_urls": ["https://a.example.com"],
        "detected_techs": {"nginx", "cloudflare"},
        "http_results": [{"url": "https://a.example.com", "webserver": "nginx"}],
        "gau_urls": {"https://a.example.com/x"},
        "crawled_urls": ["https://a.example.com/y"],
        "all_target_urls": ["https://a.example.com/x"],
        "cred_urls": [],
        "favicon_findings": [],
        "prog_type": "web",
    }


def test_checkpoint_roundtrip_restores_sets():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "recon_checkpoint.json")
        _save_recon_checkpoint(path, _sample())
        loaded = _load_recon_checkpoint(path)
    assert loaded is not None
    assert loaded["all_subdomains"] == {"a.example.com", "b.example.com"}
    assert loaded["detected_techs"] == {"nginx", "cloudflare"}
    assert isinstance(loaded["gau_urls"], set)
    assert loaded["live_urls"] == ["https://a.example.com"]


def test_missing_or_corrupt_checkpoint_returns_none():
    with tempfile.TemporaryDirectory() as d:
        assert _load_recon_checkpoint(os.path.join(d, "nope.json")) is None
        bad = os.path.join(d, "bad.json")
        open(bad, "w").write("{not json")
        assert _load_recon_checkpoint(bad) is None
