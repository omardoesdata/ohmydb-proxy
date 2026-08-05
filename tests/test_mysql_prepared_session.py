from __future__ import annotations

import pytest

from sql_safety_proxy.adapters.mysql.protocol import (
    MySqlProtocolError,
)
from sql_safety_proxy.adapters.mysql.session import (
    MySqlPreparedStatement,
    MySqlSessionState,
)


def test_begin_prepare_records_pending_sql():
    state = MySqlSessionState(database="app_db")

    state.begin_statement_prepare(
        "UPDATE safety_users SET active = ? WHERE id = ?"
    )

    assert (
        state.pending_statement_sql
        == "UPDATE safety_users SET active = ? WHERE id = ?"
    )


def test_begin_prepare_rejects_empty_sql():
    state = MySqlSessionState(database="app_db")

    with pytest.raises(
        MySqlProtocolError,
        match="cannot be empty",
    ):
        state.begin_statement_prepare("   ")


def test_begin_prepare_rejects_second_pending_prepare():
    state = MySqlSessionState(database="app_db")
    state.begin_statement_prepare("SELECT ?")

    with pytest.raises(
        MySqlProtocolError,
        match="already pending",
    ):
        state.begin_statement_prepare("SELECT 2")


def test_complete_prepare_registers_statement():
    state = MySqlSessionState(database="app_db")
    state.begin_statement_prepare(
        "UPDATE safety_users SET active = ? WHERE id = ?"
    )

    statement = state.complete_statement_prepare(
        statement_id=42,
        parameter_count=2,
        column_count=0,
    )

    assert statement == MySqlPreparedStatement(
        statement_id=42,
        sql="UPDATE safety_users SET active = ? WHERE id = ?",
        parameter_count=2,
        column_count=0,
    )
    assert state.prepared_statements[42] == statement
    assert state.pending_statement_sql is None


def test_complete_prepare_requires_pending_sql():
    state = MySqlSessionState(database="app_db")

    with pytest.raises(
        MySqlProtocolError,
        match="No MySQL statement prepare is pending",
    ):
        state.complete_statement_prepare(
            statement_id=1,
            parameter_count=0,
            column_count=0,
        )


def test_prepare_error_discards_pending_sql():
    state = MySqlSessionState(database="app_db")
    state.begin_statement_prepare("SELECT ?")

    state.fail_statement_prepare()

    assert state.pending_statement_sql is None
    assert state.prepared_statements == {}


def test_get_prepared_statement_requires_known_id():
    state = MySqlSessionState(database="app_db")

    with pytest.raises(
        MySqlProtocolError,
        match="Unknown MySQL prepared statement id 99",
    ):
        state.get_prepared_statement(99)


def test_close_prepared_statement_removes_it():
    state = MySqlSessionState(database="app_db")
    state.begin_statement_prepare("SELECT ?")
    state.complete_statement_prepare(
        statement_id=7,
        parameter_count=1,
        column_count=1,
    )

    removed = state.close_prepared_statement(7)

    assert removed.statement_id == 7
    assert state.prepared_statements == {}


def test_close_unknown_prepared_statement_is_idempotent():
    state = MySqlSessionState(database="app_db")

    assert state.close_prepared_statement(77) is None
