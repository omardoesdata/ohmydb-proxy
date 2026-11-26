from sql_safety_proxy.fail_safe import (
    FailSafeMode,
    ProtocolGapAction,
    evaluate_protocol_gap,
)


def test_strict_protocol_gap_blocks():
    result = evaluate_protocol_gap(
        FailSafeMode.STRICT,
        "unknown portal",
    )

    assert result.action == ProtocolGapAction.BLOCK
    assert "strict fail-safe mode blocks" in result.reason
