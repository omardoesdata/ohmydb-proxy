from __future__ import annotations

from sql_safety_proxy.cli import build_options


def clear_database_environment(monkeypatch) -> None:
    for variable in (
        "DATABASE_ADAPTER",
        "DATABASE_ENGINE",
        "SQL_DIALECT",
        "DB_HOST",
        "DB_PORT",
        "DB_NAME",
    ):
        monkeypatch.delenv(variable, raising=False)


def test_build_options_uses_postgres_defaults(monkeypatch):
    clear_database_environment(monkeypatch)

    options = build_options()

    assert options.adapter_name == "postgres"
    assert options.database_engine == "postgres"
    assert options.database_name == "postgres"
    assert options.target_host == "127.0.0.1"
    assert options.target_port == 5432
    assert options.dialect == "postgres"


def test_build_options_uses_mysql_database_configuration(monkeypatch):
    clear_database_environment(monkeypatch)

    monkeypatch.setenv("DATABASE_ADAPTER", "mysql")
    monkeypatch.setenv("DB_NAME", "sql_safety_v06")

    options = build_options()

    assert options.adapter_name == "mysql"
    assert options.database_engine == "mysql"
    assert options.database_name == "sql_safety_v06"
    assert options.target_host == "127.0.0.1"
    assert options.target_port == 3306
    assert options.dialect == "mysql"


def test_build_options_resolves_mariadb_alias(monkeypatch):
    clear_database_environment(monkeypatch)

    monkeypatch.setenv("DATABASE_ADAPTER", "mariadb")
    monkeypatch.setenv("DB_NAME", "sql_safety_v06")
    monkeypatch.setenv("DB_PORT", "3308")

    options = build_options()

    assert options.adapter_name == "mysql"
    assert options.database_engine == "mysql"
    assert options.database_name == "sql_safety_v06"
    assert options.target_port == 3308
    assert options.dialect == "mysql"
