import pytest

from sql_safety_proxy.adapters.base import (
    DatabaseAdapter,
    DatabaseCapabilities,
)
from sql_safety_proxy.adapters.registry import (
    get_adapter,
    list_adapters,
    register_adapter,
    resolve_adapter_name,
)


def test_postgres_adapter_resolves_aliases():
    assert get_adapter("postgres").name == "postgres"
    assert get_adapter("postgresql").name == "postgres"
    assert get_adapter("PG").name == "postgres"


def test_postgres_capabilities_are_explicit():
    capabilities = get_adapter("postgres").capabilities

    assert capabilities.network_proxy is True
    assert capabilities.simple_query is True
    assert capabilities.prepared_statements is True
    assert capabilities.transaction_state is True
    assert capabilities.impact_estimation is True
    assert capabilities.tls_termination is False
    assert capabilities.binary_parameter_oids is False


def test_registry_lists_postgres_once():
    names = [adapter.name for adapter in list_adapters()]
    assert names.count("postgres") == 1


def test_legacy_configuration_resolves_to_postgres():
    assert (
        resolve_adapter_name(
            None,
            legacy_engine="postgresql",
        )
        == "postgres"
    )
    assert (
        resolve_adapter_name(
            None,
            legacy_dialect="pg",
        )
        == "postgres"
    )


def test_unsupported_adapter_error_lists_available_adapters():
    with pytest.raises(ValueError) as exc_info:
        get_adapter("oracle")

    message = str(exc_info.value)

    assert "Unsupported database adapter 'oracle'" in message
    assert "Available adapters:" in message
    assert "mysql" in message
    assert "postgres" in message

def test_mysql_and_mariadb_resolve_to_same_adapter():
    mysql = get_adapter("mysql")
    mariadb = get_adapter("mariadb")

    assert mysql is mariadb
    assert mysql.name == "mysql"
    assert mysql.dialect == "mysql"
    assert mysql.default_port == 3306
    assert mysql.capabilities.simple_query is True
    assert mysql.capabilities.prepared_statements is False
    assert mysql.capabilities.impact_estimation is True


def test_registry_lists_mysql_and_postgres():
    names = {
        adapter.name
        for adapter in list_adapters()
    }

    assert {"mysql", "postgres"} <= names
