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

def test_permissive_protocol_gap_includes_reason():
    result = evaluate_protocol_gap(
        FailSafeMode.PERMISSIVE,
        "unknown portal",
    )

    assert result.action == ProtocolGapAction.ALLOW
    assert result.reason == (
        "unknown portal; permissive fail-safe mode allows forwarding"
    )

def test_balanced_protocol_gap_handles_empty_reason():
    result = evaluate_protocol_gap(
        FailSafeMode.BALANCED,
        "",
    )

    assert result.action == ProtocolGapAction.BLOCK
    assert result.reason == (
        "; balanced fail-safe mode blocks uninspectable SQL"
    )

def test_strict_protocol_gap_preserves_detailed_reason():
    result = evaluate_protocol_gap(
        FailSafeMode.STRICT,
        "Execute referenced unknown portal 'p42'",
    )

    assert result.action == ProtocolGapAction.BLOCK
    assert "unknown portal 'p42'" in result.reason
    assert "strict fail-safe mode blocks uninspectable SQL" in result.reason

def test_balanced_protocol_gap_empty_reason():
    result = evaluate_protocol_gap(
        FailSafeMode.BALANCED,
        "",
    )

    assert result.action == ProtocolGapAction.BLOCK
    assert result.reason == (
        "; balanced fail-safe mode blocks uninspectable SQL"
    )

def test_strict_protocol_gap_preserves_portal_reason():
    result = evaluate_protocol_gap(
        FailSafeMode.STRICT,
        "Execute referenced unknown portal 'p42'",
    )

    assert result.action == ProtocolGapAction.BLOCK
    assert "unknown portal 'p42'" in result.reason

def test_permissive_protocol_gap_preserves_multiline_reason():
    result = evaluate_protocol_gap(
        FailSafeMode.PERMISSIVE,
        "Malformed frontend message: line 1`nline 2",
    )

    assert result.action == ProtocolGapAction.ALLOW
    assert "Malformed frontend message" in result.reason
    assert "line 2" in result.reason

def test_fail_safe_mode_values():
    assert FailSafeMode.STRICT.value == "strict"
    assert FailSafeMode.BALANCED.value == "balanced"
    assert FailSafeMode.PERMISSIVE.value == "permissive"

def test_protocol_gap_action_values():
    assert ProtocolGapAction.ALLOW.value == "ALLOW"
    assert ProtocolGapAction.BLOCK.value == "BLOCK"
