from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from sql_safety_proxy.confirmation import AutoDenyProvider
from sql_safety_proxy.policy import (
    PolicyAction,
    PolicyConfig,
)
from sql_safety_proxy.proxy import (
    ProxyOptions,
    _evaluate_and_decide,
)
from sql_safety_proxy.sql_classifier import classify


def build_options(
    policy_config: PolicyConfig,
    provider=None,
) -> ProxyOptions:
    return ProxyOptions(
        listen_port=5433,
        target_host="localhost",
        target_port=5432,
        dialect="postgres",
        estimator_user="postgres",
        estimator_password="postgres",
        confirmation_provider=provider or AutoDenyProvider(),
        policy_config=policy_config,
    )


@pytest.mark.asyncio
async def test_allow_does_not_open_confirmation():
    provider = SimpleNamespace(
        confirm=AsyncMock(return_value=False)
    )

    opts = build_options(
        PolicyConfig(auto_allow_max_rows=5),
        provider,
    )

    approved, decision = await _evaluate_and_decide(
        sql="UPDATE users SET active = false WHERE id = 1",
        protocol="extended",
        classification=classify(
            "UPDATE users SET active = false WHERE id = 1"
        ),
        estimated_rows=1,
        estimate_error=None,
        approximate=False,
        database="testdb",
        opts=opts,
    )

    assert approved is True
    assert decision.action == PolicyAction.ALLOW
    provider.confirm.assert_not_awaited()


@pytest.mark.asyncio
async def test_block_does_not_open_confirmation():
    provider = SimpleNamespace(
        confirm=AsyncMock(return_value=True)
    )

    opts = build_options(
        PolicyConfig(block_at_rows=100),
        provider,
    )

    approved, decision = await _evaluate_and_decide(
        sql="DELETE FROM users WHERE id > 0",
        protocol="extended",
        classification=classify(
            "DELETE FROM users WHERE id > 0"
        ),
        estimated_rows=500,
        estimate_error=None,
        approximate=False,
        database="testdb",
        opts=opts,
    )

    assert approved is False
    assert decision.action == PolicyAction.BLOCK
    provider.confirm.assert_not_awaited()


@pytest.mark.asyncio
async def test_confirm_calls_confirmation_provider():
    provider = SimpleNamespace(
        confirm=AsyncMock(return_value=True)
    )

    opts = build_options(
        PolicyConfig(auto_allow_max_rows=5),
        provider,
    )

    classification = classify(
        "UPDATE users SET active = false WHERE id <= 50"
    )

    approved, decision = await _evaluate_and_decide(
        sql="UPDATE users SET active = false WHERE id <= 50",
        protocol="extended",
        classification=classification,
        estimated_rows=50,
        estimate_error=None,
        approximate=False,
        database="testdb",
        opts=opts,
    )

    assert approved is True
    assert decision.action == PolicyAction.CONFIRM
    provider.confirm.assert_awaited_once()

    context = provider.confirm.await_args.args[0]

    assert context.database == "testdb"
    assert context.policy_decision == decision
    assert context.estimated_rows == 50


@pytest.mark.asyncio
async def test_no_where_hard_block_skips_popup():
    provider = SimpleNamespace(
        confirm=AsyncMock(return_value=True)
    )

    opts = build_options(
        PolicyConfig(
            no_where_action=PolicyAction.BLOCK
        ),
        provider,
    )

    approved, decision = await _evaluate_and_decide(
        sql="UPDATE users SET active = false",
        protocol="extended",
        classification=classify(
            "UPDATE users SET active = false"
        ),
        estimated_rows=5000,
        estimate_error=None,
        approximate=False,
        database="testdb",
        opts=opts,
    )

    assert approved is False
    assert decision.action == PolicyAction.BLOCK
    provider.confirm.assert_not_awaited()


