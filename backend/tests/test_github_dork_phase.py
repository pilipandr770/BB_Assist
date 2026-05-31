from backend.services.phases import github_dork_phase


async def _fake_run_github_dork(scope_domains, _out_path, _token):
    return [{"repo": "org/repo", "severity": "high"}] if scope_domains else []


async def test_run_github_dork_phase_emits_events(monkeypatch):
    monkeypatch.setattr(github_dork_phase.tool_runner, "run_github_dork", _fake_run_github_dork)

    events = []

    async def emit(event_type, data):
        events.append((event_type, data))

    findings = await github_dork_phase.run_github_dork_phase(
        scope_domains=["*.example.com"],
        scan_dir="/tmp",
        github_token="",
        emit=emit,
    )

    assert len(findings) == 1
    assert any(e[0] == "phase_start" and e[1].get("phase") == "github_dork" for e in events)
    assert any(e[0] == "tool_done" and e[1].get("tool") == "github_dork" for e in events)
