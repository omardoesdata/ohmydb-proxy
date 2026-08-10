import pytest

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

def test_begin_is_safe_transaction_control():
    result = classify("BEGIN", "postgres")
    assert result.risk == "safe"
    assert result.statement_type == "TRANSACTION"
    assert result.impact_kind == "transaction"


def test_commit_is_safe_transaction_control():
    result = classify("COMMIT", "postgres")
    assert result.risk == "safe"
    assert result.statement_type == "COMMIT"


def test_rollback_is_safe_transaction_control():
    result = classify("ROLLBACK", "postgres")
    assert result.risk == "safe"
    assert result.statement_type == "ROLLBACK"


@pytest.mark.parametrize(
    "sql,dialect",
    [
        ("SET NAMES 'utf8mb4' COLLATE 'utf8mb4_general_ci'", "mysql"),
        ("SET autocommit=0", "mysql"),
        ("SET SESSION TRANSACTION READ ONLY", "mysql"),
        ("SET search_path TO public", "postgres"),
    ],
)
def test_session_local_set_is_safe(sql, dialect):
    result = classify(sql, dialect=dialect)
    assert result.risk == "safe"
    assert result.statement_type == "SET"


@pytest.mark.parametrize(
    "sql",
    [
        "SET GLOBAL max_connections=100",
        "SET PASSWORD = 'secret'",
        "SET PERSIST max_connections=100",
    ],
)
def test_global_or_credential_set_is_not_auto_allowed(sql):
    result = classify(sql, dialect="mysql")
    assert result.risk != "safe"
