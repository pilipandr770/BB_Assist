from backend.services.policy_rules import detect_no_automation_policy


def test_detect_no_automation_policy_matches_manual_preferred():
    blocked, matches = detect_no_automation_policy(
        "Please refrain from automated tools. Manual testing preferred for this program."
    )
    assert blocked is True
    assert "manual testing preferred" in matches


def test_detect_no_automation_policy_when_clean_notes():
    blocked, matches = detect_no_automation_policy(
        "Automated scanning is allowed at <=10 requests per second with disclosure header."
    )
    assert blocked is False
    assert matches == []
