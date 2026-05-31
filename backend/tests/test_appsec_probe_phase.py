from backend.models import Scope
from backend.services.phases import appsec_probe_phase


async def _fake_403_bypass(_urls, _out_path):
    return [{"url": "https://app.example.com/admin", "bypass_type": "header", "severity": "high", "payload": "X-Original-URL", "status": 200}]


async def _fake_arjun(_url, _out_path):
    return ["id", "token"]


async def _fake_dalfox(_url, _params, _out_path):
    return [{"url": _url, "param": _params[0], "evidence": "reflected payload"}]


async def test_run_appsec_probe_phase(monkeypatch):
    monkeypatch.setattr(appsec_probe_phase.tool_runner, "run_403_bypass", _fake_403_bypass)
    monkeypatch.setattr(appsec_probe_phase.tool_runner, "run_arjun", _fake_arjun)
    monkeypatch.setattr(appsec_probe_phase.tool_runner, "run_dalfox", _fake_dalfox)

    events = []

    async def emit(event_type, data):
        events.append((event_type, data))

    scope = Scope(in_scope_domains=["*.example.com"], in_scope_urls=["https://app.example.com"])
    result = await appsec_probe_phase.run_appsec_probe_phase(
        scan_dir="/tmp",
        scope=scope,
        all_target_urls=["https://app.example.com/api/v1/users"],
        ffuf_403_urls=["https://app.example.com/admin"],
        do_arjun=True,
        arjun_max=5,
        program_type="web",
        session_cookies="",
        auth_header="",
        emit=emit,
    )

    assert len(result["bypasses"]) == 1
    assert len(result["arjun_params"]) == 1
    assert len(result["dalfox_findings"]) == 1
    assert any(e[0] == "phase_start" and e[1].get("phase") == "bypass_403" for e in events)
    assert any(e[0] == "phase_done" and e[1].get("phase") == "xss_scan" for e in events)
