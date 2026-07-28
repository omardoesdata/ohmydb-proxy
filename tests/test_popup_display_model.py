from sql_safety_proxy.confirmation import QueryContext
from sql_safety_proxy.policy import (
    PolicyAction,
    PolicyConfig,
    evaluate_policy,
)
from sql_safety_proxy.popup_confirmation import (
    build_display_model,
)
from sql_safety_proxy.sql_classifier import classify


def test_display_model_contains_policy_and_query_details():
    classification = classify(
        "UPDATE users SET active = false WHERE id <= 100"
    )

    decision = evaluate_policy(
        classification=classification,
        estimated_rows=100,
        estimate_error=None,
        config=PolicyConfig(),
    )

    context = QueryContext(
        sql="UPDATE users SET active = false WHERE id <= 100",
        classification=classification,
        estimated_rows=100,
        policy_decision=decision,
        database="testdb",
    )

    model = build_display_model(context)

    assert model.severity == "HIGH"
    assert model.policy_action == "CONFIRM"
    assert model.operation == "UPDATE"
    assert model.database == "testdb"
    assert model.target_table == "users"
    assert model.estimated_rows == "100"
    assert "confirmation" in model.policy_reason.lower()


def test_display_model_marks_approximate_estimate():
    classification = classify(
        "DELETE FROM users WHERE id <= 25"
    )

    decision = evaluate_policy(
        classification=classification,
        estimated_rows=25,
        estimate_error=None,
        config=PolicyConfig(),
    )

    context = QueryContext(
        sql="DELETE FROM users WHERE id <= $1",
        classification=classification,
        estimated_rows=25,
        policy_decision=decision,
        database="testdb",
        approximate_estimate=True,
    )

    model = build_display_model(context)

    assert model.estimated_rows == "25 (approximate)"


def test_display_model_handles_estimation_error():
    classification = classify(
        "UPDATE users SET active = false WHERE id <= 100"
    )

    decision = evaluate_policy(
        classification=classification,
        estimated_rows=None,
        estimate_error="connection timeout",
        config=PolicyConfig(),
    )

    context = QueryContext(
        sql="UPDATE users SET active = false WHERE id <= 100",
        classification=classification,
        estimated_rows=None,
        estimate_error="connection timeout",
        policy_decision=decision,
        database="testdb",
    )

    model = build_display_model(context)

    assert model.estimated_rows == "Unavailable"
    assert model.estimate_note == "connection timeout"


def test_display_model_uses_critical_severity_for_no_where():
    classification = classify(
        "UPDATE users SET active = false"
    )

    decision = evaluate_policy(
        classification=classification,
        estimated_rows=5000,
        estimate_error=None,
        config=PolicyConfig(),
    )

    context = QueryContext(
        sql="UPDATE users SET active = false",
        classification=classification,
        estimated_rows=5000,
        policy_decision=decision,
        database="testdb",
    )

    model = build_display_model(context)

    assert model.severity == "CRITICAL"
    assert model.target_table == "users"
    assert model.estimated_rows == "5,000"
