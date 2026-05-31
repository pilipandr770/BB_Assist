from backend.models import Scope
from backend.services.phases import active_recon_phase


async def _emit_collector(events, event_type, data):
    events.append((event_type, data))


async def _fake_subfinder(domains, out_path):
    return ["api.example.com", "www.example.com"]


async def _fake_dnsx(subdomains, out_path):
    return ["api.example.com"]


async def _fake_nmap(live_hosts, out_path):
    return ["https://api.example.com:8443"], [
        {
            "host": "api.example.com",
            "port": 8443,
            "service": "nginx",
            "version": "1.24.0",
            "fingerprint": "nginx 1.24.0",
        }
    ]


def _fake_match(service_versions):
    return [{"cve": "CVE-2024-0001"}] if service_versions else []


async def test_run_active_recon_core_emits_events(monkeypatch):
    monkeypatch.setattr(active_recon_phase.tool_runner, "run_subfinder", _fake_subfinder)
    monkeypatch.setattr(active_recon_phase.tool_runner, "run_dnsx", _fake_dnsx)
    monkeypatch.setattr(active_recon_phase.tool_runner, "run_nmap", _fake_nmap)
    monkeypatch.setattr(active_recon_phase.tool_runner, "match_service_versions_to_cves", _fake_match)

    events = []

    async def emit(event_type, data):
        await _emit_collector(events, event_type, data)

    scope = Scope(in_scope_domains=["*.example.com"])
    result = await active_recon_phase.run_active_recon_core(
        scope=scope,
        recon_dir="/tmp",
        seed_subdomains={"old.example.com"},
        emit=emit,
    )

    assert "all_subdomains" in result
    assert "api.example.com" in result["all_subdomains"]
    assert result["live_hosts"] == ["api.example.com"]
    assert len(result["nmap_service_versions"]) == 1
    assert any(evt[0] == "tool_start" and evt[1].get("tool") == "subfinder" for evt in events)
    assert any(evt[0] == "tool_done" and evt[1].get("tool") == "cve_csv" for evt in events)
