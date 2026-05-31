from backend.models import Scope
from backend.services.phases import content_and_js_phase


def _fake_ffuf_selector(_live_urls, max_hosts=5):
    return ["https://app.example.com"][:max_hosts]


def _fake_resolve_ffuf_wordlist(_path):
    return "/wordlists/common.txt"


async def _fake_run_ffuf(_host_url, _wordlist, _out_path, session_cookies="", auth_header=""):
    return [
        {"status": 200, "input": {"FUZZ": "admin"}},
        {"status": 403, "input": {"FUZZ": "secret"}},
    ]


async def _fake_run_js_scanner(_js_urls, _out_path):
    return [
        {"context": "NEXT_PUBLIC_KEY=something", "match": "public", "secret_type": "public", "severity": "low", "url": "https://app.example.com/app.js"},
        {"context": "upliftApiKey=secret", "match": "secret", "secret_type": "api_key", "severity": "high", "url": "https://app.example.com/app.js"},
    ]


async def test_run_content_and_js_phase(monkeypatch):
    monkeypatch.setattr(content_and_js_phase.tool_runner, "resolve_ffuf_wordlist", _fake_resolve_ffuf_wordlist)
    monkeypatch.setattr(content_and_js_phase.tool_runner, "run_ffuf", _fake_run_ffuf)
    monkeypatch.setattr(content_and_js_phase.tool_runner, "run_js_scanner", _fake_run_js_scanner)

    events = []

    async def emit(event_type, data):
        events.append((event_type, data))

    scope = Scope(in_scope_domains=["*.example.com"], in_scope_urls=["https://app.example.com"])

    result = await content_and_js_phase.run_content_and_js_phase(
        scan_dir="/tmp",
        scope=scope,
        live_urls=["https://app.example.com"],
        all_target_urls=["https://app.example.com/app.js"],
        gau_urls={"https://app.example.com/app.js"},
        crawled_urls=[],
        do_ffuf=True,
        program_type="web",
        ffuf_target_selector=_fake_ffuf_selector,
        session_cookies="",
        auth_header="",
        emit=emit,
    )

    assert len(result["ffuf_found_urls"]) == 1
    assert len(result["ffuf_403_urls"]) == 1
    assert len(result["js_secrets"]) == 1  # public marker filtered out
    assert any(e[0] == "phase_start" and e[1].get("phase") == "content_discovery" for e in events)
    assert any(e[0] == "phase_done" and e[1].get("phase") == "js_scan" for e in events)
