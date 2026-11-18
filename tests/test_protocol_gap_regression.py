from sql_safety_proxy.fail_safe import (
    FailSafeMode,
    ProtocolGapAction,
    evaluate_protocol_gap,
)


def test_balanced_protocol_gap_blocks_unknown_operation():
    result = evaluate_protocol_gap(
        FailSafeMode.BALANCED,
        "unknown operation",
    )

    assert result.action == ProtocolGapAction.BLOCK

def test_balanced_protocol_gap_includes_reason():
    result = evaluate_protocol_gap(
        FailSafeMode.BALANCED,
        "unknown operation",
    )

    assert result.reason == (
        "unknown operation; balanced fail-safe mode blocks uninspectable SQL"
    )

def test_strict_protocol_gap_includes_reason():
    result = evaluate_protocol_gap(
        FailSafeMode.STRICT,
        "malformed frontend message",
    )

    assert result.action == ProtocolGapAction.BLOCK
    assert result.reason == (
        "malformed frontend message; strict fail-safe mode blocks uninspectable SQL"
    )

def test_permissive_protocol_gap_includes_reason():
    result = evaluate_protocol_gap(
        FailSafeMode.PERMISSIVE,
        "unknown portal",
    )

    assert result.action == ProtocolGapAction.ALLOW
    assert result.reason == (
        "unknown portal; permissive fail-safe mode allows forwarding"
    )
