import json

from backend.services.phases import delta_history_phase


async def test_emit_delta_new_surface_emits_when_new_items_found():
    events = []

    async def emit(event_type, data):
        events.append((event_type, data))

    await delta_history_phase.emit_delta_new_surface(
        prev_subdomains={"a.example.com"},
        prev_live_urls={"https://a.example.com"},
        all_subdomains={"a.example.com", "b.example.com"},
        live_urls=["https://a.example.com", "https://b.example.com"],
        emit=emit,
    )

    assert len(events) == 1
    assert events[0][0] == "delta_new_surface"
    assert events[0][1]["new_subdomains_count"] == 1


async def test_load_and_save_delta_history(tmp_path):
    events = []

    async def emit(event_type, data):
        events.append((event_type, data))

    delta_file = str(tmp_path / "scan_history.json")

    await delta_history_phase.save_delta_history(
        delta_file=delta_file,
        scan_id="scan-1",
        all_subdomains={"a.example.com"},
        live_urls=["https://a.example.com"],
    )

    loaded = await delta_history_phase.load_delta_baseline(
        delta_file=delta_file,
        emit=emit,
    )

    assert "a.example.com" in loaded["prev_subdomains"]
    assert "https://a.example.com" in loaded["prev_live_urls"]
    assert any(evt[0] == "delta_baseline" for evt in events)

    with open(delta_file, encoding="utf-8") as handle:
        data = json.load(handle)
    assert data["scan_id"] == "scan-1"
