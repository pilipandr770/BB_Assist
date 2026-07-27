from backend.services import tool_runner


async def _fake_screenshot(url, screenshot_file):
    return {"saved": True, "path": screenshot_file, "error": None, "_url_used": url}


async def test_capture_finding_evidence_js_scanner_screenshots_matched_url(monkeypatch):
    async def _fake_http_evidence(*_a, **_k):
        return {}

    async def _fake_validate_key(*_a, **_k):
        return {}

    monkeypatch.setattr(tool_runner, "capture_page_screenshot", _fake_screenshot)
    monkeypatch.setattr(tool_runner, "capture_http_evidence", _fake_http_evidence)
    monkeypatch.setattr(tool_runner, "validate_api_key", _fake_validate_key)

    raw = {
        "_source": "js_scanner",
        "matched-at": "https://app.example.com/app.js",
        "extracted-results": ["AIzaSyFAKE"],
        "_secret_type": "google_api_key",
    }
    evidence = await tool_runner.capture_finding_evidence(raw, "", "shot.png")
    assert evidence["screenshot"]["saved"] is True
    assert evidence["screenshot"]["_url_used"] == "https://app.example.com/app.js"


async def test_capture_finding_evidence_subdomain_takeover_screenshots_matched_url(monkeypatch):
    monkeypatch.setattr(tool_runner, "capture_page_screenshot", _fake_screenshot)

    raw = {"_source": "subdomain_takeover", "matched-at": "https://old.example.com"}
    evidence = await tool_runner.capture_finding_evidence(raw, "", "shot.png")
    assert evidence["screenshot"]["saved"] is True
    assert evidence["screenshot"]["_url_used"] == "https://old.example.com"


async def test_capture_finding_evidence_dalfox_screenshots_poc_url_not_matched_at(monkeypatch):
    monkeypatch.setattr(tool_runner, "capture_page_screenshot", _fake_screenshot)

    raw = {
        "_source": "dalfox",
        "matched-at": "https://app.example.com/search?q=%3Cscript%3E",
        "_poc_url": "https://app.example.com/search?q=%3Cscript%3E",
    }
    evidence = await tool_runner.capture_finding_evidence(raw, "", "shot.png")
    assert evidence["screenshot"]["saved"] is True
    assert "script" in evidence["screenshot"]["_url_used"]


async def test_capture_finding_evidence_unknown_source_no_screenshot(monkeypatch):
    called = False

    async def _tracking_screenshot(url, screenshot_file):
        nonlocal called
        called = True
        return {"saved": True}

    monkeypatch.setattr(tool_runner, "capture_page_screenshot", _tracking_screenshot)

    raw = {"_source": "cors_checker", "matched-at": "https://app.example.com"}
    evidence = await tool_runner.capture_finding_evidence(raw, "", "shot.png")
    assert evidence["screenshot"] is None
    assert called is False


async def test_capture_finding_evidence_no_screenshot_file_skips_capture(monkeypatch):
    called = False

    async def _tracking_screenshot(url, screenshot_file):
        nonlocal called
        called = True
        return {"saved": True}

    monkeypatch.setattr(tool_runner, "capture_page_screenshot", _tracking_screenshot)

    raw = {"_source": "subdomain_takeover", "matched-at": "https://old.example.com"}
    evidence = await tool_runner.capture_finding_evidence(raw, "", screenshot_file=None)
    assert evidence["screenshot"] is None
    assert called is False
