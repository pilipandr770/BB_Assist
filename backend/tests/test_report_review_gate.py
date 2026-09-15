"""
Review-gate tests: a report must be explicitly marked reviewed
(POST .../review) before it can be submitted to HackerOne
(POST .../submit) — separate from just clicking submit itself.
"""
import json
import os

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.routers import reports


def _make_client():
    app = FastAPI()
    app.include_router(reports.router, prefix="/api/reports")
    return TestClient(app)


def _write_program(program_dir, h1_program_handle=None):
    os.makedirs(program_dir, exist_ok=True)
    with open(os.path.join(program_dir, "program.json"), "w") as f:
        json.dump({
            "id": "prog1", "name": "Test Program", "slug": "prog1",
            "raw_text": "scope: *.example.com",
            "h1_program_handle": h1_program_handle,
        }, f)


def _write_report(reports_dir, reviewed=False, reviewed_at=None):
    os.makedirs(reports_dir, exist_ok=True)
    with open(os.path.join(reports_dir, "rep1.md"), "w") as f:
        f.write("# [HIGH] Test vuln\n\nBody.\n")
    with open(os.path.join(reports_dir, "rep1.json"), "w") as f:
        json.dump({
            "id": "rep1", "finding_id": "finding1", "program_id": "prog1",
            "title": "Test vuln", "severity": "high",
            "reviewed": reviewed, "reviewed_at": reviewed_at,
        }, f)


def test_mark_reviewed_sets_flag_and_timestamp(tmp_path, monkeypatch):
    monkeypatch.setattr(reports, "WORKSPACE", str(tmp_path))
    _write_report(tmp_path / "prog1" / "reports")

    client = _make_client()
    resp = client.post("/api/reports/prog1/rep1/review", json={"note": "looks solid"})
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["reviewed"] is True
    assert data["reviewed_at"] is not None
    assert data["review_note"] == "looks solid"

    with open(tmp_path / "prog1" / "reports" / "rep1.json") as f:
        persisted = json.load(f)
    assert persisted["reviewed"] is True


def test_mark_reviewed_404_when_report_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(reports, "WORKSPACE", str(tmp_path))
    client = _make_client()
    resp = client.post("/api/reports/prog1/nope/review", json={})
    assert resp.status_code == 404


def test_submit_rejects_unreviewed_report(tmp_path, monkeypatch):
    monkeypatch.setattr(reports, "WORKSPACE", str(tmp_path))
    monkeypatch.setattr(reports.settings, "h1_username", "researcher")
    monkeypatch.setattr(reports.settings, "h1_api_token", "token")

    called = False

    async def _tracking_submit(**_kwargs):
        nonlocal called
        called = True
        return {"success": True, "h1_report_id": "1", "h1_report_url": "https://hackerone.com/reports/1"}

    monkeypatch.setattr(reports.h1_api_service, "submit_report", _tracking_submit)

    _write_program(tmp_path / "prog1", h1_program_handle="acme")
    _write_report(tmp_path / "prog1" / "reports", reviewed=False)

    client = _make_client()
    resp = client.post("/api/reports/prog1/rep1/submit", json={})
    assert resp.status_code == 400
    assert "reviewed" in resp.json()["detail"].lower()
    assert called is False


def test_submit_proceeds_once_reviewed(tmp_path, monkeypatch):
    monkeypatch.setattr(reports, "WORKSPACE", str(tmp_path))
    monkeypatch.setattr(reports.settings, "h1_username", "researcher")
    monkeypatch.setattr(reports.settings, "h1_api_token", "token")

    async def _fake_submit(**_kwargs):
        return {"success": True, "h1_report_id": "42", "h1_report_url": "https://hackerone.com/reports/42"}

    async def _fake_notify(**_kwargs):
        return None

    monkeypatch.setattr(reports.h1_api_service, "submit_report", _fake_submit)
    monkeypatch.setattr(reports.telegram_notifier, "send_report_submitted", _fake_notify)

    _write_program(tmp_path / "prog1", h1_program_handle="acme")
    _write_report(tmp_path / "prog1" / "reports", reviewed=True, reviewed_at="2026-01-01T00:00:00Z")

    client = _make_client()
    resp = client.post("/api/reports/prog1/rep1/submit", json={})
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["success"] is True
    assert data["h1_report_id"] == "42"

    with open(tmp_path / "prog1" / "reports" / "rep1.json") as f:
        persisted = json.load(f)
    assert persisted["h1_submitted"] is True


async def test_save_report_initializes_unreviewed(tmp_path, monkeypatch):
    from backend.models import Report, Severity
    from backend.services import report_generator

    monkeypatch.setattr(report_generator.settings, "workspace_dir", str(tmp_path))

    report = Report(
        id="rep2", finding_id="finding2", program_id="prog2",
        markdown="# [LOW] Test\n", title="Test", severity=Severity.low,
    )

    await report_generator.save_report(report, "prog2", quality=None)

    with open(tmp_path / "prog2" / "reports" / "rep2.json") as f:
        meta = json.load(f)
    assert meta["reviewed"] is False
    assert meta["reviewed_at"] is None
