import pytest

from sql_safety_proxy.policy import (
    PolicyAction,
    PolicyConfig,
    Severity,
    evaluate_policy,
)
from sql_safety_proxy.sql_classifier import classify


def test_select_is_allowed():
    classification = classify("SELECT * FROM users")

    decision = evaluate_policy(
        classification,
        estimated_rows=None,
        estimate_error=None,
        config=PolicyConfig(),
    )

    assert decision.action == PolicyAction.ALLOW
    assert decision.severity == Severity.LOW


def test_update_without_where_is_critical():
    classification = classify(
        "UPDATE users SET active = false"
    )

    decision = evaluate_policy(
        classification,
        estimated_rows=5000,
        estimate_error=None,
        config=PolicyConfig(),
    )

    assert decision.action == PolicyAction.CONFIRM
    assert decision.severity == Severity.CRITICAL
    assert classification.target_table == "users"
    assert classification.has_where is False


def test_update_without_where_can_be_hard_blocked():
    classification = classify(
        "UPDATE users SET active = false"
    )

    decision = evaluate_policy(
        classification,
        estimated_rows=5000,
        estimate_error=None,
        config=PolicyConfig(
            no_where_action=PolicyAction.BLOCK
        ),
    )

    assert decision.action == PolicyAction.BLOCK


def test_small_filtered_update_can_be_auto_allowed():
    classification = classify(
        "UPDATE users SET active = false WHERE id = 1"
    )

    decision = evaluate_policy(
        classification,
        estimated_rows=1,
        estimate_error=None,
        config=PolicyConfig(
            auto_allow_max_rows=5
        ),
    )

    assert decision.action == PolicyAction.ALLOW
    assert decision.severity == Severity.LOW
    assert classification.has_where is True


def test_filtered_update_requires_confirmation():
    classification = classify(
        "UPDATE users SET active = false WHERE id <= 50"
    )

    decision = evaluate_policy(
        classification,
        estimated_rows=50,
        estimate_error=None,
        config=PolicyConfig(
            auto_allow_max_rows=5
        ),
    )

    assert decision.action == PolicyAction.CONFIRM
    assert decision.severity == Severity.MEDIUM


def test_large_filtered_delete_is_blocked():
    classification = classify(
        "DELETE FROM users WHERE id > 0"
    )

    decision = evaluate_policy(
        classification,
        estimated_rows=15000,
        estimate_error=None,
        config=PolicyConfig(
            block_at_rows=10000
        ),
    )

    assert decision.action == PolicyAction.BLOCK
    assert decision.severity == Severity.CRITICAL


def test_estimation_failure_can_be_blocked():
    classification = classify(
        "UPDATE users SET active = false WHERE id <= 100"
    )

    decision = evaluate_policy(
        classification,
        estimated_rows=None,
        estimate_error="connection timeout",
        config=PolicyConfig(
            estimation_failure_action=PolicyAction.BLOCK
        ),
    )

    assert decision.action == PolicyAction.BLOCK
    assert decision.severity == Severity.HIGH


def test_drop_uses_structural_policy():
    classification = classify("DROP TABLE users")

    decision = evaluate_policy(
        classification,
        estimated_rows=None,
        estimate_error=None,
        config=PolicyConfig(
            structural_action=PolicyAction.BLOCK
        ),
    )

    assert decision.action == PolicyAction.BLOCK
    assert decision.severity == Severity.CRITICAL
    assert classification.target_table == "users"


def test_invalid_threshold_configuration_fails():
    with pytest.raises(ValueError):
        PolicyConfig(
            auto_allow_max_rows=100,
            block_at_rows=100,
        )
