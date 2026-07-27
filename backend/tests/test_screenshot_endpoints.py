import os

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.routers import reports, scans


def _make_client(router, prefix):
    app = FastAPI()
    app.include_router(router, prefix=prefix)
    return TestClient(app)


def test_scans_screenshot_endpoint_serves_existing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(scans, "WORKSPACE", str(tmp_path))
    scan_dir = tmp_path / "prog1" / "scans" / "scan1"
    scan_dir.mkdir(parents=True)
    (scan_dir / "evidence_finding1.png").write_bytes(b"\x89PNG\r\n\x1a\nfake")

    client = _make_client(scans.router, "/api/scans")
    resp = client.get("/api/scans/prog1/scan1/findings/finding1/screenshot")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/png"
    assert resp.content.startswith(b"\x89PNG")


def test_scans_screenshot_endpoint_404_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(scans, "WORKSPACE", str(tmp_path))
    client = _make_client(scans.router, "/api/scans")
    resp = client.get("/api/scans/prog1/scan1/findings/nope/screenshot")
    assert resp.status_code == 404


def test_scans_screenshot_endpoint_rejects_path_traversal(tmp_path, monkeypatch):
    monkeypatch.setattr(scans, "WORKSPACE", str(tmp_path))
    client = _make_client(scans.router, "/api/scans")
    resp = client.get("/api/scans/prog1/scan1/findings/..%2F..%2Fetc%2Fpasswd/screenshot")
    assert resp.status_code in (400, 404)


def test_reports_screenshot_endpoint_serves_via_finding_lookup(tmp_path, monkeypatch):
    monkeypatch.setattr(reports, "WORKSPACE", str(tmp_path))

    program_dir = tmp_path / "prog1"
    (program_dir / "reports").mkdir(parents=True)
    (program_dir / "findings" / "filtered").mkdir(parents=True)
    scan_dir = program_dir / "scans" / "scan1"
    scan_dir.mkdir(parents=True)

    import json
    (program_dir / "reports" / "rep1.json").write_text(json.dumps({
        "id": "rep1", "finding_id": "finding1", "program_id": "prog1", "title": "t", "severity": "high",
    }))
    (program_dir / "findings" / "filtered" / "finding1.json").write_text(json.dumps({
        "id": "finding1", "scan_id": "scan1", "program_id": "prog1", "tool": "dalfox",
        "title": "t", "url": "https://app.example.com", "severity": "high",
        "vuln_type": "xss", "raw_output": "{}",
    }))
    (scan_dir / "evidence_finding1.png").write_bytes(b"\x89PNG\r\n\x1a\nfake")

    client = _make_client(reports.router, "/api/reports")
    resp = client.get("/api/reports/prog1/rep1/screenshot")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/png"


def test_reports_screenshot_endpoint_404_when_no_screenshot_captured(tmp_path, monkeypatch):
    monkeypatch.setattr(reports, "WORKSPACE", str(tmp_path))

    program_dir = tmp_path / "prog1"
    (program_dir / "reports").mkdir(parents=True)
    (program_dir / "findings" / "filtered").mkdir(parents=True)
    (program_dir / "scans" / "scan1").mkdir(parents=True)

    import json
    (program_dir / "reports" / "rep1.json").write_text(json.dumps({
        "id": "rep1", "finding_id": "finding1", "program_id": "prog1", "title": "t", "severity": "high",
    }))
    (program_dir / "findings" / "filtered" / "finding1.json").write_text(json.dumps({
        "id": "finding1", "scan_id": "scan1", "program_id": "prog1", "tool": "cors_checker",
        "title": "t", "url": "https://app.example.com", "severity": "high",
        "vuln_type": "cors-misconfig", "raw_output": "{}",
    }))
    # No evidence_finding1.png written — screenshot was never captured for this source.

    client = _make_client(reports.router, "/api/reports")
    resp = client.get("/api/reports/prog1/rep1/screenshot")
    assert resp.status_code == 404


def test_reports_screenshot_endpoint_404_when_report_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(reports, "WORKSPACE", str(tmp_path))
    client = _make_client(reports.router, "/api/reports")
    resp = client.get("/api/reports/prog1/nope/screenshot")
    assert resp.status_code == 404
