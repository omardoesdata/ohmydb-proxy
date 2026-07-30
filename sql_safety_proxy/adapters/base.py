"""Shared contracts for database adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sql_safety_proxy.risk_estimator import DbConnectionOptions


@dataclass(frozen=True)
class DatabaseCapabilities:
    network_proxy: bool
    simple_query: bool
    prepared_statements: bool
    named_portals: bool
    transaction_state: bool
    impact_estimation: bool
    tls_termination: bool
    binary_parameter_oids: bool

    def as_dict(self) -> dict[str, bool]:
        return {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
        }


class DatabaseAdapter(ABC):
    name: str
    aliases: tuple[str, ...]
    display_name: str
    dialect: str
    default_port: int
    capabilities: DatabaseCapabilities

    @abstractmethod
    async def estimate_rows(
        self,
        preview_query: str,
        options: "DbConnectionOptions",
    ) -> int:
        raise NotImplementedError

    @abstractmethod
    async def start_proxy(self, options: Any) -> None:
        raise NotImplementedError

    def validate_runtime(self, options: Any) -> None:
        for variable, value in (
            ("DB_PORT", options.target_port),
            ("PROXY_PORT", options.listen_port),
        ):
            if value <= 0 or value > 65535:
                raise ValueError(f"{variable} must be between 1 and 65535")