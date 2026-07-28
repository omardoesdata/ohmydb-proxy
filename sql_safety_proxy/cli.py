"""Command-line entry point and environment configuration."""

from __future__ import annotations

import asyncio
import os

from .audit import JsonlAuditLogger
from .confirmation import CliConfirmationProvider
from .fail_safe import FailSafeMode
from .policy import PolicyAction, PolicyConfig
from .popup_confirmation import PopupConfirmationProvider
from .proxy import ProxyOptions, start_intercepting_proxy


def build_confirmation_provider():
    mode = os.environ.get("CONFIRMATION_MODE", "popup").strip().lower()
    if mode == "popup":
        return PopupConfirmationProvider()
    if mode == "cli":
        return CliConfirmationProvider()
    raise ValueError("CONFIRMATION_MODE must be either 'popup' or 'cli'")


def read_policy_action(
    variable_name: str,
    default: PolicyAction,
) -> PolicyAction:
    raw_value = os.environ.get(
        variable_name,
        default.value,
    ).strip().upper()

    try:
        return PolicyAction(raw_value)
    except ValueError as exc:
        allowed = ", ".join(action.value for action in PolicyAction)
        raise ValueError(
            f"{variable_name} must be one of: {allowed}"
        ) from exc


def read_boolean(variable_name: str, default: bool) -> bool:
    raw_value = os.environ.get(
        variable_name,
        "true" if default else "false",
    ).strip().lower()

    if raw_value in {"1", "true", "yes", "on"}:
        return True
    if raw_value in {"0", "false", "no", "off"}:
        return False

    raise ValueError(
        f"{variable_name} must be true/false, yes/no, on/off, or 1/0"
    )


def read_fail_safe_mode() -> FailSafeMode:
    raw_value = os.environ.get(
        "FAIL_SAFE_MODE",
        FailSafeMode.BALANCED.value,
    ).strip().lower()

    try:
        return FailSafeMode(raw_value)
    except ValueError as exc:
        allowed = ", ".join(mode.value for mode in FailSafeMode)
        raise ValueError(
            f"FAIL_SAFE_MODE must be one of: {allowed}"
        ) from exc


def build_policy_config() -> PolicyConfig:
    return PolicyConfig(
        auto_allow_max_rows=int(
            os.environ.get("POLICY_AUTO_ALLOW_MAX_ROWS", "0")
        ),
        block_at_rows=int(
            os.environ.get("POLICY_BLOCK_AT_ROWS", "10000")
        ),
        no_where_action=read_policy_action(
            "POLICY_NO_WHERE_ACTION",
            PolicyAction.CONFIRM,
        ),
        structural_action=read_policy_action(
            "POLICY_STRUCTURAL_ACTION",
            PolicyAction.CONFIRM,
        ),
        unknown_action=read_policy_action(
            "POLICY_UNKNOWN_ACTION",
            PolicyAction.CONFIRM,
        ),
        estimation_failure_action=read_policy_action(
            "POLICY_ESTIMATION_FAILURE_ACTION",
            PolicyAction.CONFIRM,
        ),
    )


def build_audit_logger() -> JsonlAuditLogger:
    return JsonlAuditLogger(
        path=os.environ.get(
            "AUDIT_LOG_PATH",
            "logs/sql-safety-audit.jsonl",
        ),
        enabled=read_boolean("AUDIT_ENABLED", True),
    )


def build_options() -> ProxyOptions:
    return ProxyOptions(
        listen_port=int(os.environ.get("PROXY_PORT", "5433")),
        target_host=os.environ.get("DB_HOST", "127.0.0.1"),
        target_port=int(os.environ.get("DB_PORT", "5432")),
        dialect=os.environ.get("SQL_DIALECT", "postgres"),
        estimator_user=os.environ.get("ESTIMATOR_USER", "postgres"),
        estimator_password=os.environ.get("ESTIMATOR_PASSWORD", ""),
        confirmation_provider=build_confirmation_provider(),
        database_engine=os.environ.get("DATABASE_ENGINE", "postgres"),
        estimate_timeout_seconds=float(
            os.environ.get("ESTIMATE_TIMEOUT_SECONDS", "8")
        ),
        policy_config=build_policy_config(),
        audit_logger=build_audit_logger(),
        fail_safe_mode=read_fail_safe_mode(),
    )


def main() -> None:
    try:
        asyncio.run(start_intercepting_proxy(build_options()))
    except KeyboardInterrupt:
        print("\n[proxy] stopped")


if __name__ == "__main__":
    main()
