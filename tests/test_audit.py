import json

import pytest

from sql_safety_proxy.audit import (
    JsonlAuditLogger,
    build_audit_event,
)


def make_event():
    return build_audit_event(
        sql="UPDATE users SET active = false",
        database="testdb",
        operation="UPDATE",
        target_table="users",
        severity="CRITICAL",
        policy_action="BLOCK",
        final_decision="BLOCKED_BY_POLICY",
        estimated_rows=5000,
        estimate_error=None,
        classification_reason="UPDATE has no WHERE clause",
        policy_reason="Full-table mutation blocked",
        approximate_estimate=False,
        protocol="extended",
    )


@pytest.mark.asyncio
async def test_jsonl_audit_logger_writes_valid_event(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    logger = JsonlAuditLogger(audit_path)

    await logger.log(make_event())

    lines = audit_path.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(lines) == 1

    payload = json.loads(lines[0])

    assert payload["database"] == "testdb"
    assert payload["operation"] == "UPDATE"
    assert payload["target_table"] == "users"
    assert payload["severity"] == "CRITICAL"
    assert payload["policy_action"] == "BLOCK"
    assert payload["final_decision"] == "BLOCKED_BY_POLICY"
    assert payload["estimated_rows"] == 5000
    assert payload["protocol"] == "extended"
    assert payload["timestamp"]


@pytest.mark.asyncio
async def test_jsonl_audit_logger_appends_events(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    logger = JsonlAuditLogger(audit_path)

    await logger.log(make_event())
    await logger.log(make_event())

    lines = audit_path.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(lines) == 2


@pytest.mark.asyncio
async def test_disabled_audit_logger_writes_nothing(tmp_path):
    audit_path = tmp_path / "audit.jsonl"

    logger = JsonlAuditLogger(
        audit_path,
        enabled=False,
    )

    await logger.log(make_event())

    assert not audit_path.exists()
