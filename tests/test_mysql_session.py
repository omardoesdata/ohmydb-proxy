from __future__ import annotations

import pytest

from sql_safety_proxy.adapters.mysql.protocol import (
    MySqlProtocolError,
)
from sql_safety_proxy.adapters.mysql.session import (
    MySqlSessionState,
)


def test_database_change_waits_for_backend_ok():
    state = MySqlSessionState(database="original_db")

    state.begin_database_change("new_db")

    assert state.database == "original_db"
    assert state.pending_database == "new_db"


def test_backend_ok_commits_database_change():
    state = MySqlSessionState(database="original_db")
    state.begin_database_change("new_db")

    changed = state.complete_database_change(b"\x00")

    assert changed is True
    assert state.database == "new_db"
    assert state.pending_database is None


def test_backend_error_rejects_database_change():
    state = MySqlSessionState(database="original_db")
    state.begin_database_change("missing_db")

    changed = state.complete_database_change(
        b"\xff\x19\x04#42000Unknown database"
    )

    assert changed is False
    assert state.database == "original_db"
    assert state.pending_database is None


def test_database_name_is_trimmed():
    state = MySqlSessionState(database="original_db")

    state.begin_database_change("  new_db  ")

    assert state.pending_database == "new_db"


def test_empty_database_name_is_rejected():
    state = MySqlSessionState(database="original_db")

    with pytest.raises(
        MySqlProtocolError,
        match="cannot be empty",
    ):
        state.begin_database_change("   ")


def test_second_database_change_is_rejected_while_pending():
    state = MySqlSessionState(database="original_db")
    state.begin_database_change("first_db")

    with pytest.raises(
        MySqlProtocolError,
        match="already pending",
    ):
        state.begin_database_change("second_db")


def test_response_without_pending_change_is_rejected():
    state = MySqlSessionState(database="original_db")

    with pytest.raises(
        MySqlProtocolError,
        match="No MySQL database change is pending",
    ):
        state.complete_database_change(b"\x00")


def test_empty_backend_response_clears_pending_change():
    state = MySqlSessionState(database="original_db")
    state.begin_database_change("new_db")

    with pytest.raises(
        MySqlProtocolError,
        match="backend response is empty",
    ):
        state.complete_database_change(b"")

    assert state.database == "original_db"
    assert state.pending_database is None


def test_unexpected_backend_response_clears_pending_change():
    state = MySqlSessionState(database="original_db")
    state.begin_database_change("new_db")

    with pytest.raises(
        MySqlProtocolError,
        match="Unexpected backend response",
    ):
        state.complete_database_change(b"\x01\x04")

    assert state.database == "original_db"
    assert state.pending_database is None


def test_mark_closing_records_quit_state():
    state = MySqlSessionState(database="original_db")

    state.mark_closing()

    assert state.closing is True
