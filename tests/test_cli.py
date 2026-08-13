from __future__ import annotations

import pytest

from sql_safety_proxy import __version__
from sql_safety_proxy import cli
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



def test_main_help_does_not_start_proxy(monkeypatch, capsys):
    def fail_if_options_are_built():
        raise AssertionError("proxy configuration must not be built for --help")

    monkeypatch.setattr(cli, "build_options", fail_if_options_are_built)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--help"])

    assert exc_info.value.code == 0

    output = capsys.readouterr().out
    assert "SQL Safety Proxy" in output
    assert "--version" in output


def test_main_version_does_not_start_proxy(monkeypatch, capsys):
    def fail_if_options_are_built():
        raise AssertionError(
            "proxy configuration must not be built for --version"
        )

    monkeypatch.setattr(cli, "build_options", fail_if_options_are_built)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--version"])

    assert exc_info.value.code == 0

    output = capsys.readouterr().out.strip()
    assert output == f"sql-safety-proxy {__version__}"


def test_main_reports_configuration_error_without_traceback(
    monkeypatch,
    capsys,
):
    monkeypatch.setenv("CONFIRMATION_MODE", "invalid-mode")

    result = cli.main([])

    assert result == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "configuration error:" in captured.err
    assert "CONFIRMATION_MODE" in captured.err
    assert "Traceback" not in captured.err



def test_cli_arguments_override_environment(monkeypatch):
    clear_database_environment(monkeypatch)

    monkeypatch.setenv("DATABASE_ADAPTER", "postgres")
    monkeypatch.setenv("PROXY_PORT", "5433")
    monkeypatch.setenv("DB_HOST", "env-host")
    monkeypatch.setenv("DB_PORT", "5432")
    monkeypatch.setenv("DB_NAME", "env-db")

    args = cli.build_parser().parse_args(
        [
            "--adapter",
            "mysql",
            "--port",
            "13307",
            "--db-host",
            "cli-host",
            "--db-port",
            "13306",
            "--db-name",
            "cli-db",
        ]
    )

    options = build_options(args)

    assert options.adapter_name == "mysql"
    assert options.database_engine == "mysql"
    assert options.dialect == "mysql"
    assert options.listen_port == 13307
    assert options.target_host == "cli-host"
    assert options.target_port == 13306
    assert options.database_name == "cli-db"


def test_cli_mariadb_alias_resolves_to_mysql(monkeypatch):
    clear_database_environment(monkeypatch)

    args = cli.build_parser().parse_args(
        [
            "--adapter",
            "mariadb",
            "--db-name",
            "example",
        ]
    )

    options = build_options(args)

    assert options.adapter_name == "mysql"
    assert options.database_engine == "mysql"
    assert options.dialect == "mysql"
    assert options.target_port == 3306


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["--port", "0"], "must be between 1 and 65535"),
        (["--port", "65536"], "must be between 1 and 65535"),
        (["--db-port", "0"], "must be between 1 and 65535"),
        (["--db-port", "65536"], "must be between 1 and 65535"),
    ],
)
def test_cli_rejects_invalid_ports(arguments, message):
    args = cli.build_parser().parse_args(arguments)

    with pytest.raises(ValueError, match=message):
        build_options(args)


def test_startup_summary_does_not_expose_password(
    monkeypatch,
    capsys,
):
    sentinel = "DO_NOT_PRINT_THIS_SECRET_94731"

    monkeypatch.setenv(
        "ESTIMATOR_PASSWORD",
        sentinel,
    )

    async def fake_start(options):
        assert options.estimator_password == sentinel

    monkeypatch.setattr(
        cli,
        "start_intercepting_proxy",
        fake_start,
    )

    result = cli.main(
        [
            "--adapter",
            "postgres",
            "--db-name",
            "safe_test_db",
        ]
    )

    assert result == 0

    captured = capsys.readouterr()

    assert "[proxy] configuration:" in captured.out
    assert "adapter=postgres" in captured.out
    assert "database=safe_test_db" in captured.out
    assert sentinel not in captured.out
    assert sentinel not in captured.err
