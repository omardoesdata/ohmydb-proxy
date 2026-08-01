"""Database adapter registration and lookup."""

from __future__ import annotations

from threading import RLock

from .base import DatabaseAdapter

_LOCK = RLock()
_ADAPTERS: dict[str, DatabaseAdapter] = {}
_ALIASES: dict[str, str] = {}
_BUILTINS_LOADED = False


def _normalize(value: str) -> str:
    normalized = value.strip().lower()
    if not normalized:
        raise ValueError("Database adapter name cannot be empty")
    return normalized


def register_adapter(
    adapter: DatabaseAdapter,
    *,
    replace: bool = False,
) -> None:
    name = _normalize(adapter.name)
    aliases = {_normalize(alias) for alias in adapter.aliases}
    aliases.add(name)

    with _LOCK:
        if name in _ADAPTERS and not replace:
            raise ValueError(
                f"Database adapter {name!r} is already registered"
            )

        for alias in aliases:
            owner = _ALIASES.get(alias)
            if owner and owner != name and not replace:
                raise ValueError(
                    f"Database adapter alias {alias!r} belongs to {owner!r}"
                )

        _ADAPTERS[name] = adapter
        for alias in aliases:
            _ALIASES[alias] = name


def _load_builtins() -> None:
    global _BUILTINS_LOADED

    if _BUILTINS_LOADED:
        return

    with _LOCK:
        if _BUILTINS_LOADED:
            return

        from .mysql.adapter import MYSQL_ADAPTER
        from .postgres.adapter import POSTGRES_ADAPTER

        register_adapter(POSTGRES_ADAPTER)
        register_adapter(MYSQL_ADAPTER)
        _BUILTINS_LOADED = True


def get_adapter(name: str) -> DatabaseAdapter:
    _load_builtins()
    key = _normalize(name)

    try:
        canonical = _ALIASES[key]
        return _ADAPTERS[canonical]
    except KeyError as exc:
        supported = ", ".join(sorted(_ADAPTERS))
        raise ValueError(
            f"Unsupported database adapter {name!r}. "
            f"Available adapters: {supported}"
        ) from exc


def resolve_adapter_name(
    explicit_adapter: str | None,
    *,
    legacy_engine: str | None = None,
    legacy_dialect: str | None = None,
) -> str:
    selected = next(
        (
            value
            for value in (
                explicit_adapter,
                legacy_engine,
                legacy_dialect,
            )
            if value and value.strip()
        ),
        "postgres",
    )
    return get_adapter(selected).name


def list_adapters() -> tuple[DatabaseAdapter, ...]:
    _load_builtins()
    return tuple(
        _ADAPTERS[name]
        for name in sorted(_ADAPTERS)
    )