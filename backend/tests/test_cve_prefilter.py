from backend.services import cve_enricher


async def test_filters_low_epss_and_malformed(monkeypatch):
    async def fake_epss(ids):
        return {"CVE-2020-0001": {"score": 0.5}, "CVE-2020-0002": {"score": 0.002}}

    async def fake_kev(cve):
        return cve == "CVE-2020-0003"

    monkeypatch.setattr(cve_enricher, "get_epss", fake_epss)
    monkeypatch.setattr(cve_enricher, "is_in_kev", fake_kev)
    hits = [{"cve": c} for c in ("CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003", "bogus", "CVE-2026-1")]
    kept, dropped = await cve_enricher.filter_actionable_cves(hits)
    assert [h["cve"] for h in kept] == ["CVE-2020-0001", "CVE-2020-0003"]
    assert dropped == 3


async def test_fails_open_when_epss_unavailable(monkeypatch):
    async def no_epss(ids):
        return {}

    monkeypatch.setattr(cve_enricher, "get_epss", no_epss)
    hits = [{"cve": "CVE-2020-0001"}, {"cve": "CVE-2020-0002"}]
    kept, dropped = await cve_enricher.filter_actionable_cves(hits)
    assert len(kept) == 2 and dropped == 0
