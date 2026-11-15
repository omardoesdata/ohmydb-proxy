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
