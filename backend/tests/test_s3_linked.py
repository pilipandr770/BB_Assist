from backend.services import tool_runner


def test_s3_refs_virtual_and_path_style():
    text = (
        '<img src="https://wolt-assets.s3.eu-west-1.amazonaws.com/a.png">'
        '<script src="https://s3.amazonaws.com/other-bucket/x.js"></script>'
        "cdn.s3-website-us-east-1.amazonaws.com"
    )
    refs = tool_runner._s3_refs_in_text(text)
    assert {"wolt-assets", "other-bucket", "cdn"} <= refs
    assert "wolt-prod" not in refs


async def test_unlinked_buckets_are_dropped(monkeypatch, tmp_path):
    def fake_check(bucket):
        return {"bucket": bucket, "url": f"https://{bucket}.s3.amazonaws.com/", "publicly_listed": True,
                "sample_keys": ["a.txt"], "severity": "critical", "impact": "listed."}

    monkeypatch.setattr(tool_runner, "_check_s3_bucket_sync", fake_check)
    monkeypatch.setattr(tool_runner, "_S3_BUCKET_SUFFIXES", ["", "-prod"])
    monkeypatch.setattr(tool_runner, "_collect_s3_refs_sync", lambda urls, domains: {"acme-prod"})
    res = await tool_runner.run_s3_enum(["acme.com"], str(tmp_path / "o.jsonl"), live_urls=["https://acme.com"])
    assert [r["bucket"] for r in res] == ["acme-prod"]
    assert res[0]["linked_to_target"] is True
