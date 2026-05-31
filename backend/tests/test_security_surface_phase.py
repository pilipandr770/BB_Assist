from backend.models import Scope
from backend.services.phases import security_surface_phase


async def _fake_cors_checker(_live_urls, _out_path):
    return [{"url": "https://app.example.com", "severity": "medium", "attack_type": "origin_reflection"}]


async def _fake_takeover(_subs, _out_path):
    return [{"subdomain": "old.example.com", "provider": "github", "severity": "high"}]


async def _fake_email_security(_domains, _out_path):
    return [{"domain": "example.com", "checks_failed": "DMARC", "severity": "medium", "issues": [], "impact": "spoofing"}]


async def _fake_swagger(_live_urls, _out_path):
    return [{"spec_url": "https://app.example.com/swagger.json", "base_url": "https://app.example.com", "sample_paths": ["/api/v1/users"], "endpoints_count": 1, "severity": "medium", "impact": "exposure"}]


async def _fake_s3(_domains, _out_path):
    return [{"bucket": "example-public", "severity": "high"}]


async def test_run_security_surface_phase(monkeypatch):
    monkeypatch.setattr(security_surface_phase.tool_runner, "run_cors_checker", _fake_cors_checker)
    monkeypatch.setattr(security_surface_phase.tool_runner, "run_subdomain_takeover", _fake_takeover)
    monkeypatch.setattr(security_surface_phase.tool_runner, "run_email_security", _fake_email_security)
    monkeypatch.setattr(security_surface_phase.tool_runner, "run_swagger_discovery", _fake_swagger)
    monkeypatch.setattr(security_surface_phase.tool_runner, "run_s3_enum", _fake_s3)

    events = []

    async def emit(event_type, data):
        events.append((event_type, data))

    scope = Scope(in_scope_domains=["*.example.com"], in_scope_urls=["https://app.example.com"])
    result = await security_surface_phase.run_security_surface_phase(
        scan_dir="/tmp",
        scope=scope,
        live_urls=["https://app.example.com"],
        all_subdomains={"old.example.com"},
        all_target_urls=["https://app.example.com"],
        takeover_timeout_s=10,
        emit=emit,
    )

    assert len(result["cors_findings"]) == 1
    assert len(result["takeover_findings"]) == 1
    assert len(result["email_findings"]) == 1
    assert len(result["swagger_findings"]) == 1
    assert len(result["s3_findings"]) == 1
    assert any(e[0] == "phase_start" and e[1].get("phase") == "cors_check" for e in events)
    assert any(e[0] == "phase_done" and e[1].get("phase") == "s3_enum" for e in events)
