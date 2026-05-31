import os

# Ensure settings import works in test environments without real secrets.
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key")

from backend.services import claude_service


def test_model_chain_starts_with_task_primary():
    chain = claude_service._model_chain("report")
    assert len(chain) >= 1
    assert chain[0] == claude_service._TASK_MODELS["report"]


def test_usage_delta_since_zero_for_same_snapshot():
    snap = claude_service.get_usage_snapshot()
    delta = claude_service.usage_delta_since(snap)
    assert delta["calls"] == 0
    assert delta["input_tokens"] == 0
    assert delta["output_tokens"] == 0


def test_usage_increment_updates_snapshot():
    before = claude_service.get_usage_snapshot()
    claude_service._usage_increment(
        task="filter",
        model="claude-sonnet-4-6",
        input_tokens=1000,
        output_tokens=500,
    )
    after = claude_service.get_usage_snapshot()
    delta = claude_service._usage_diff(after, before)

    assert delta["calls"] == 1
    assert delta["input_tokens"] == 1000
    assert delta["output_tokens"] == 500
    assert "filter" in delta["by_task"]
    assert "claude-sonnet-4-6" in delta["by_model"]
    assert delta["estimated_cost_usd"] > 0
