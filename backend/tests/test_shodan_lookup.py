import socket

from backend.services import tool_runner


class _FakeResponse:
    def __init__(self, status_code, json_data=None):
        self.status_code = status_code
        self._json = json_data or {}

    def json(self):
        return self._json


_HOST_DATA = {
    "1.2.3.4": _FakeResponse(200, {
        "ip_str": "1.2.3.4",
        "data": [
            {"port": 443, "product": "nginx", "version": "1.18.0"},
            {"port": 22, "product": "OpenSSH", "version": "7.4"},
            {"port": 8080, "product": "", "version": ""},  # no product/version — skipped
        ],
        "vulns": ["CVE-2021-23017", "CVE-2019-9511"],
    }),
    "5.6.7.8": _FakeResponse(404),
    "9.9.9.9": _FakeResponse(401),
}


class _FakeAsyncClient:
    def __init__(self, *_a, **_k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False

    async def get(self, url, params=None):
        ip = url.rstrip("/").split("/")[-1]
        return _HOST_DATA.get(ip, _FakeResponse(404))


def _fake_gethostbyname(host):
    mapping = {
        "app.example.com": "1.2.3.4",
        "api.example.com": "1.2.3.4",  # shares an IP — should dedupe to one lookup
        "gone.example.com": "5.6.7.8",
    }
    if host not in mapping:
        raise socket.gaierror("unresolvable")
    return mapping[host]


async def test_run_shodan_lookup_extracts_services_and_vulns(monkeypatch):
    monkeypatch.setattr(tool_runner._httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setattr(socket, "gethostbyname", _fake_gethostbyname)
    monkeypatch.setattr(tool_runner.asyncio, "sleep", lambda *_a, **_k: _noop())

    result = await tool_runner.run_shodan_lookup(
        ["app.example.com", "api.example.com", "gone.example.com"],
        api_key="fake-key",
    )

    services = result["service_versions"]
    vulns = result["vuln_findings"]

    # nginx + openssh extracted; the empty-product/version banner is skipped
    assert len(services) == 2
    assert {s["service"] for s in services} == {"nginx", "OpenSSH"}
    # both example.com hosts share IP 1.2.3.4 -> attributed to the first one seen
    assert all(s["host"] == "app.example.com" for s in services)

    assert {v["cve"] for v in vulns} == {"CVE-2021-23017", "CVE-2019-9511"}
    assert all(v["ip"] == "1.2.3.4" for v in vulns)


async def test_run_shodan_lookup_stops_on_invalid_key(monkeypatch):
    monkeypatch.setattr(tool_runner._httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setattr(socket, "gethostbyname", lambda h: "9.9.9.9")
    monkeypatch.setattr(tool_runner.asyncio, "sleep", lambda *_a, **_k: _noop())

    result = await tool_runner.run_shodan_lookup(["bad.example.com"], api_key="invalid")
    assert result == {"service_versions": [], "vuln_findings": []}


async def test_run_shodan_lookup_no_key_returns_empty_without_requests(monkeypatch):
    called = False

    class _TrackingClient(_FakeAsyncClient):
        async def get(self, *a, **k):
            nonlocal called
            called = True
            return _FakeResponse(200, {})

    monkeypatch.setattr(tool_runner._httpx, "AsyncClient", _TrackingClient)
    result = await tool_runner.run_shodan_lookup(["app.example.com"], api_key="")
    assert result == {"service_versions": [], "vuln_findings": []}
    assert called is False


async def _noop():
    return None
