from backend.models import Scope
from backend.services.phases import url_recon_phase


async def _fake_run_httpx(targets, out_path, session_cookies="", auth_header=""):
    return [{"url": "https://api.example.com"}]


async def _fake_run_nmap(live_hosts, out_path):
    return [], []


def _fake_match_service_versions(_service_versions):
    return []


def _fake_extract_tech_stack(_http_results):
    return {"nginx", "react"}


def _fake_extract_service_versions_from_httpx(_http_results):
    return []


async def _fake_run_gau(_domain, _out_path):
    return {
        "https://api.example.com/v1/items",
        "https://user@example.com:Passw0rd@api.example.com/private",
    }


async def _fake_run_katana(_urls, _out_path, session_cookies="", auth_header=""):
    return ["https://api.example.com/app.js"]


async def test_run_url_recon_phase_basic(monkeypatch):
    monkeypatch.setattr(url_recon_phase.tool_runner, "run_httpx", _fake_run_httpx)
    monkeypatch.setattr(url_recon_phase.tool_runner, "run_nmap", _fake_run_nmap)
    monkeypatch.setattr(url_recon_phase.tool_runner, "match_service_versions_to_cves", _fake_match_service_versions)
    monkeypatch.setattr(url_recon_phase.tool_runner, "extract_tech_stack", _fake_extract_tech_stack)
    monkeypatch.setattr(url_recon_phase.tool_runner, "extract_service_versions_from_httpx", _fake_extract_service_versions_from_httpx)
    monkeypatch.setattr(url_recon_phase.tool_runner, "run_gau", _fake_run_gau)
    monkeypatch.setattr(url_recon_phase.tool_runner, "run_katana", _fake_run_katana)

    events = []

    async def emit(event_type, data):
        events.append((event_type, data))

    scope = Scope(
        in_scope_domains=["*.example.com"],
        in_scope_urls=["https://example.com"],
    )

    result = await url_recon_phase.run_url_recon_phase(
        scope=scope,
        recon_dir="/tmp",
        live_hosts=["api.example.com"],
        nmap_endpoints=[],
        nmap_service_versions=[{"host": "api.example.com", "port": 443, "service": "nginx", "version": "1.24.0"}],
        nmap_csv_cve_hits=[],
        do_katana=True,
        program_type="web",
        session_cookies="",
        auth_header="",
        emit=emit,
    )

    assert "https://api.example.com" in result["live_urls"]
    assert "react" in result["detected_techs"]
    assert len(result["all_target_urls"]) >= 1
    assert len(result["cred_urls"]) == 1
    assert any(e[0] == "tool_start" and e[1].get("tool") == "httpx" for e in events)
    assert any(e[0] == "tool_done" and e[1].get("tool") == "gau" for e in events)
