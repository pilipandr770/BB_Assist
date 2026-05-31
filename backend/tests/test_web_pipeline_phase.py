"""Tests for web_pipeline_phase helpers."""

import json
import pytest

from backend.services.phases.web_pipeline_phase import (
    nuclei_to_finding,
    select_ffuf_targets,
    select_nuclei_targets,
)


# ── select_nuclei_targets ─────────────────────────────────────────────────────

def test_select_nuclei_targets_prefers_live_urls():
    live = ["https://example.com/api/users?id=1"]
    all_urls = live + ["https://example.com/static/logo.png", "https://example.com/"]
    result = select_nuclei_targets(all_urls, live, max_urls=10)
    assert "https://example.com/api/users?id=1" in result


def test_select_nuclei_targets_skips_static_extensions():
    urls = ["https://example.com/style.css", "https://example.com/bg.png"]
    result = select_nuclei_targets(urls, [], max_urls=10)
    assert result == []


def test_select_nuclei_targets_caps_at_max_urls():
    urls = [f"https://example.com/path/{i}?x={i}" for i in range(1000)]
    result = select_nuclei_targets(urls, [], max_urls=50)
    assert len(result) <= 50


def test_select_nuclei_targets_deduplicates_by_path():
    urls = [
        "https://example.com/api/users?a=1",
        "https://example.com/api/users?b=2",
    ]
    # Both share the same (netloc, path) key — only the higher-scored one survives
    result = select_nuclei_targets(urls, [], max_urls=10)
    assert len(result) == 1


# ── select_ffuf_targets ───────────────────────────────────────────────────────

def test_select_ffuf_targets_prefers_api_subdomain():
    urls = [
        "https://cdn.example.com/",
        "https://api.example.com/",
        "https://www.example.com/",
    ]
    result = select_ffuf_targets(urls, max_hosts=2)
    assert "https://api.example.com" in result


def test_select_ffuf_targets_skips_cdn_hosts():
    urls = ["https://cdn.example.com/", "https://static.example.com/"]
    result = select_ffuf_targets(urls, max_hosts=5)
    assert result == []


def test_select_ffuf_targets_caps_at_max_hosts():
    urls = [f"https://sub{i}.example.com/" for i in range(20)]
    result = select_ffuf_targets(urls, max_hosts=3)
    assert len(result) <= 3


# ── nuclei_to_finding ─────────────────────────────────────────────────────────

class _FakeJob:
    id = "scan-1"
    program_id = "prog-1"


def test_nuclei_to_finding_maps_fields():
    raw = {
        "info": {"name": "XSS Found", "severity": "high", "tags": ["xss"]},
        "matched-at": "https://example.com/search?q=<script>",
        "type": "http",
    }
    finding = nuclei_to_finding(raw, _FakeJob())
    assert finding.title == "XSS Found"
    assert finding.severity.value == "high"
    assert finding.url == "https://example.com/search?q=<script>"
    assert finding.scan_id == "scan-1"
    assert finding.program_id == "prog-1"


def test_nuclei_to_finding_unknown_severity_defaults_to_informative():
    raw = {
        "info": {"name": "Test", "severity": "bananas"},
        "matched-at": "https://example.com/",
        "type": "http",
    }
    finding = nuclei_to_finding(raw, _FakeJob())
    assert finding.severity.value == "informative"


def test_nuclei_to_finding_stores_raw_json():
    raw = {"info": {"name": "T", "severity": "low"}, "matched-at": "https://x.com/"}
    finding = nuclei_to_finding(raw, _FakeJob())
    assert json.loads(finding.raw_output) == raw
