"""Command-line entry point for SQL Safety Proxy."""
from __future__ import annotations

import asyncio
import os

from .confirmation import CliConfirmationProvider
from .popup_confirmation import PopupConfirmationProvider
from .proxy import ProxyOptions, start_intercepting_proxy


def build_confirmation_provider():
    mode = os.environ.get("CONFIRMATION_MODE", "popup").strip().lower()
    if mode == "popup":
        return PopupConfirmationProvider()
    if mode == "cli":
        return CliConfirmationProvider()
    raise ValueError("CONFIRMATION_MODE must be either 'popup' or 'cli'")


def build_options() -> ProxyOptions:
    return ProxyOptions(
        listen_port=int(os.environ.get("PROXY_PORT", "5433")),
        target_host=os.environ.get("DB_HOST", "127.0.0.1"),
        target_port=int(os.environ.get("DB_PORT", "5432")),
        dialect=os.environ.get("SQL_DIALECT", "postgres"),
        estimator_user=os.environ.get("ESTIMATOR_USER", "postgres"),
        estimator_password=os.environ.get("ESTIMATOR_PASSWORD", ""),
        confirmation_provider=build_confirmation_provider(),
    )


def main() -> None:
    try:
        asyncio.run(start_intercepting_proxy(build_options()))
    except KeyboardInterrupt:
        print("\n[proxy] stopped")


if __name__ == "__main__":
    main()
