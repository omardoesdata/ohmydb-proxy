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

def test_balanced_protocol_gap_blocks():
    result = evaluate_protocol_gap(
        FailSafeMode.BALANCED,
        "unknown prepared statement",
    )

    assert result.action == ProtocolGapAction.BLOCK
    assert "balanced fail-safe mode blocks" in result.reason

def test_permissive_protocol_gap_allows():
    result = evaluate_protocol_gap(
        FailSafeMode.PERMISSIVE,
        "unknown portal",
    )

    assert result.action == ProtocolGapAction.ALLOW
    assert "permissive fail-safe mode allows forwarding" in result.reason
