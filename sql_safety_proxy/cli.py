"""Command-line entry point and environment configuration."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from collections.abc import Sequence

from . import __version__
from .adapters.registry import get_adapter, resolve_adapter_name
from .audit import JsonlAuditLogger
from .confirmation import CliConfirmationProvider
from .fail_safe import FailSafeMode
from .policy import PolicyAction, PolicyConfig
from .popup_confirmation import PopupConfirmationProvider
from .proxy import ProxyOptions, start_intercepting_proxy


def _cli_or_env(
    args: argparse.Namespace | None,
    attribute: str,
    variable_name: str,
    default: str,
) -> str:
    if args is not None:
        value = getattr(args, attribute, None)
        if value is not None:
            return str(value)

    return os.environ.get(variable_name, default)


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


def read_positive_int(
    variable_name: str,
    default: int,
    minimum: int = 1,
) -> int:
    value = int(os.environ.get(variable_name, str(default)))
    if value < minimum:
        raise ValueError(
            f"{variable_name} must be at least {minimum}"
        )
    return value


def read_positive_float(
    variable_name: str,
    default: float,
) -> float:
    value = float(os.environ.get(variable_name, str(default)))
    if value <= 0:
        raise ValueError(f"{variable_name} must be positive")
    return value


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
        multi_statement_action=read_policy_action(
            "POLICY_MULTI_STATEMENT_ACTION",
            PolicyAction.BLOCK,
        ),
    )


def build_audit_logger() -> JsonlAuditLogger:
    return JsonlAuditLogger(
        path=os.environ.get(
            "AUDIT_LOG_PATH",
            "logs/sql-safety-audit.jsonl",
        ),
        enabled=read_boolean("AUDIT_ENABLED", True),
        max_file_bytes=read_positive_int(
            "AUDIT_MAX_FILE_BYTES",
            10 * 1024 * 1024,
            minimum=1024,
        ),
        max_backups=read_positive_int(
            "AUDIT_MAX_BACKUPS",
            3,
        ),
        max_field_chars=read_positive_int(
            "AUDIT_MAX_FIELD_CHARS",
            4096,
            minimum=16,
        ),
    )


def build_options(
    args: argparse.Namespace | None = None,
) -> ProxyOptions:
    adapter_override = (
        getattr(args, "adapter", None)
        if args is not None
        else None
    )

    adapter_name = resolve_adapter_name(
        adapter_override
        or os.environ.get("DATABASE_ADAPTER"),
        legacy_engine=os.environ.get("DATABASE_ENGINE"),
        legacy_dialect=os.environ.get("SQL_DIALECT"),
    )

    adapter = get_adapter(adapter_name)

    listen_port = int(
        _cli_or_env(
            args,
            "port",
            "PROXY_PORT",
            "5433",
        )
    )

    target_host = _cli_or_env(
        args,
        "db_host",
        "DB_HOST",
        "127.0.0.1",
    )

    target_port = int(
        _cli_or_env(
            args,
            "db_port",
            "DB_PORT",
            str(adapter.default_port),
        )
    )

    database_name = _cli_or_env(
        args,
        "db_name",
        "DB_NAME",
        "postgres",
    )

    if not 1 <= listen_port <= 65535:
        raise ValueError("PROXY_PORT/--port must be between 1 and 65535")

    if not 1 <= target_port <= 65535:
        raise ValueError("DB_PORT/--db-port must be between 1 and 65535")

    if not target_host.strip():
        raise ValueError("DB_HOST/--db-host must not be empty")

    if not database_name.strip():
        raise ValueError("DB_NAME/--db-name must not be empty")

    return ProxyOptions(
        listen_port=listen_port,
        target_host=target_host,
        target_port=target_port,
        dialect=(
            adapter.dialect
            if adapter_override is not None
            else os.environ.get(
                "SQL_DIALECT",
                adapter.dialect,
            )
        ),
        estimator_user=os.environ.get(
            "ESTIMATOR_USER",
            "postgres",
        ),
        estimator_password=os.environ.get(
            "ESTIMATOR_PASSWORD",
            "",
        ),
        confirmation_provider=build_confirmation_provider(),
        database_engine=(
            adapter.name
            if adapter_override is not None
            else os.environ.get(
                "DATABASE_ENGINE",
                adapter.name,
            )
        ),
        adapter_name=adapter.name,
        database_name=database_name,
        estimate_timeout_seconds=float(
            os.environ.get(
                "ESTIMATE_TIMEOUT_SECONDS",
                "8",
            )
        ),
        backend_connect_timeout_seconds=read_positive_float(
            "BACKEND_CONNECT_TIMEOUT_SECONDS",
            10.0,
        ),
        socket_read_timeout_seconds=read_positive_float(
            "SOCKET_READ_TIMEOUT_SECONDS",
            300.0,
        ),
        max_message_bytes=read_positive_int(
            "MAX_PROTOCOL_MESSAGE_BYTES",
            64 * 1024 * 1024,
            minimum=1024,
        ),
        max_session_items=read_positive_int(
            "MAX_SESSION_ITEMS",
            256,
        ),
        max_session_state_bytes=read_positive_int(
            "MAX_SESSION_STATE_BYTES",
            8 * 1024 * 1024,
            minimum=1024,
        ),
        policy_config=build_policy_config(),
        audit_logger=build_audit_logger(),
        fail_safe_mode=read_fail_safe_mode(),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ohmydb",
        description=(
            "Run OhMyDB between a database client and a "
            "PostgreSQL or MySQL/MariaDB backend."
        ),
        epilog=(
            "Runtime configuration is read from environment variables. "
            "See the project README for configuration options."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--adapter",
        choices=("postgres", "mysql", "mariadb"),
        help=(
            "Database adapter. Overrides DATABASE_ADAPTER."
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        help=(
            "Local proxy listening port. Overrides PROXY_PORT."
        ),
    )
    parser.add_argument(
        "--db-host",
        help=(
            "Backend database host. Overrides DB_HOST."
        ),
    )
    parser.add_argument(
        "--db-port",
        type=int,
        help=(
            "Backend database port. Overrides DB_PORT."
        ),
    )
    parser.add_argument(
        "--db-name",
        help=(
            "Backend database name. Overrides DB_NAME."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        options = build_options(args)
    except (TypeError, ValueError) as exc:
        print(
            f"ohmydb: configuration error: {exc}",
            file=sys.stderr,
        )
        return 2

    print(
        "[proxy] configuration: "
        f"adapter={options.adapter_name}, "
        f"listen_port={options.listen_port}, "
        f"backend={options.target_host}:{options.target_port}, "
        f"database={options.database_name}, "
        f"fail_safe={options.fail_safe_mode.value}"
    )

    try:
        asyncio.run(start_intercepting_proxy(options))
    except KeyboardInterrupt:
        print("\n[proxy] stopped")
        return 130

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
