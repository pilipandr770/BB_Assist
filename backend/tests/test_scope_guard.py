"""
Defense-in-depth scope enforcement tests for the "active" tool_runner functions
(ffuf, dalfox, sqlmap, 403-bypass, cors-checker, subdomain-takeover).

Each of these now requires an explicit `scope` argument and must refuse to
execute anything against an out-of-scope target — even if the caller forgot
to pre-filter its input list. This mirrors nuclei's existing internal
`is_in_scope` check, applied consistently across every active-scanning tool.
"""
import pytest

from backend.models import Scope
from backend.services import tool_runner

IN_SCOPE = Scope(in_scope_domains=["*.example.com"], in_scope_urls=["https://app.example.com"])
OUT_OF_SCOPE_URL = "https://evil-not-my-target.com/path"
OUT_OF_SCOPE_HOST = "evil-not-my-target.com"


async def test_run_ffuf_refuses_out_of_scope(monkeypatch):
    called = False

    async def _tracking_run_command(*_a, **_k):
        nonlocal called
        called = True
        return 0, "", ""

    monkeypatch.setattr(tool_runner, "_run_command", _tracking_run_command)
    monkeypatch.setattr(tool_runner, "resolve_ffuf_wordlist", lambda _w: "/wordlists/common.txt")

    result = await tool_runner.run_ffuf(OUT_OF_SCOPE_URL, "", "/tmp/out.json", scope=IN_SCOPE)
    assert result == []
    assert called is False


async def test_run_ffuf_proceeds_for_in_scope(monkeypatch):
    called = False

    async def _tracking_run_command(*_a, **_k):
        nonlocal called
        called = True
        return 0, "", ""

    monkeypatch.setattr(tool_runner, "_run_command", _tracking_run_command)
    monkeypatch.setattr(tool_runner, "resolve_ffuf_wordlist", lambda _w: "/wordlists/common.txt")

    await tool_runner.run_ffuf("https://app.example.com", "", "/tmp/out.json", scope=IN_SCOPE)
    assert called is True


async def test_run_dalfox_refuses_out_of_scope(monkeypatch):
    called = False

    async def _tracking_run_command(*_a, **_k):
        nonlocal called
        called = True
        return 0, "", ""

    monkeypatch.setattr(tool_runner, "_run_command", _tracking_run_command)

    result = await tool_runner.run_dalfox(OUT_OF_SCOPE_URL, ["q"], "/tmp/out.json", scope=IN_SCOPE)
    assert result == []
    assert called is False


async def test_run_sqlmap_refuses_out_of_scope(monkeypatch):
    called = False

    async def _tracking_run_command(*_a, **_k):
        nonlocal called
        called = True
        return 0, "", ""

    monkeypatch.setattr(tool_runner, "_run_command", _tracking_run_command)

    result = await tool_runner.run_sqlmap(OUT_OF_SCOPE_URL, "/tmp", scope=IN_SCOPE)
    assert result == []
    assert called is False


async def test_run_403_bypass_drops_out_of_scope_targets(monkeypatch):
    calls = []

    def _tracking_bypass_sync(url):
        calls.append(url)
        return None

    monkeypatch.setattr(tool_runner, "_try_bypass_sync", _tracking_bypass_sync)

    await tool_runner.run_403_bypass(
        ["https://app.example.com/admin", OUT_OF_SCOPE_URL], "/tmp/out.jsonl", scope=IN_SCOPE
    )
    assert calls == ["https://app.example.com/admin"]


async def test_run_403_bypass_all_out_of_scope_returns_empty_without_calling(monkeypatch):
    called = False

    def _tracking_bypass_sync(url):
        nonlocal called
        called = True
        return None

    monkeypatch.setattr(tool_runner, "_try_bypass_sync", _tracking_bypass_sync)

    result = await tool_runner.run_403_bypass([OUT_OF_SCOPE_URL], "/tmp/out.jsonl", scope=IN_SCOPE)
    assert result == []
    assert called is False


async def test_run_cors_checker_drops_out_of_scope_targets(monkeypatch):
    calls = []

    def _tracking_cors_sync(url):
        calls.append(url)
        return None

    monkeypatch.setattr(tool_runner, "_test_cors_sync", _tracking_cors_sync)

    await tool_runner.run_cors_checker(
        ["https://app.example.com/api", OUT_OF_SCOPE_URL], "/tmp/out.jsonl", scope=IN_SCOPE
    )
    assert calls == ["https://app.example.com/api"]


async def test_run_subdomain_takeover_drops_out_of_scope_targets(monkeypatch):
    calls = []

    def _tracking_takeover_sync(sub):
        calls.append(sub)
        return None

    monkeypatch.setattr(tool_runner, "_check_takeover_sync", _tracking_takeover_sync)

    await tool_runner.run_subdomain_takeover(
        ["old.example.com", OUT_OF_SCOPE_HOST], "/tmp/out.jsonl", scope=IN_SCOPE
    )
    assert calls == ["old.example.com"]


def test_active_scan_functions_require_scope_kwarg():
    """scope is keyword-only and mandatory — calling without it must fail loudly,
    not silently scan without a scope check."""
    import inspect

    for fn in (
        tool_runner.run_ffuf,
        tool_runner.run_dalfox,
        tool_runner.run_sqlmap,
        tool_runner.run_403_bypass,
        tool_runner.run_cors_checker,
        tool_runner.run_subdomain_takeover,
    ):
        sig = inspect.signature(fn)
        param = sig.parameters.get("scope")
        assert param is not None, f"{fn.__name__} has no scope parameter"
        assert param.kind == inspect.Parameter.KEYWORD_ONLY, f"{fn.__name__}.scope must be keyword-only"
        assert param.default is inspect.Parameter.empty, f"{fn.__name__}.scope must be required"
