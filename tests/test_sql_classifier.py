from sql_safety_proxy.sql_classifier import classify


def test_update_without_where_gets_full_table_preview():
    result = classify("UPDATE users SET active = false;", "postgres")
    assert result.risk == "risky"
    assert result.preview_query == "SELECT COUNT(*) FROM users"


def test_delete_without_where_gets_full_table_preview():
    result = classify("DELETE FROM users;", "postgres")
    assert result.preview_query == "SELECT COUNT(*) FROM users"


def test_update_with_where_keeps_predicate():
    result = classify("UPDATE users SET active = false WHERE id <= 100;", "postgres")
    assert result.preview_query is not None
    assert "WHERE id <= 100" in result.preview_query


def test_truncate_gets_full_table_preview():
    result = classify("TRUNCATE TABLE users;", "postgres")
    assert result.preview_query == "SELECT COUNT(*) FROM users"


def test_multiple_statements_are_detected_as_critical_batch():
    result = classify("SELECT 1; DELETE FROM users;")
    assert result.risk == "risky"
    assert result.statement_type == "MULTI_STATEMENT"
    assert result.impact_kind == "batch"
    assert result.statement_count == 2
