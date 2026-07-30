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
    with pytest.raises(
        ValueError,
        match="Available adapters: postgres",
    ):
        get_adapter("mysql")


class FakeAdapter(DatabaseAdapter):
    name = "test-fake-v05"
    aliases = ("test-fake-alias-v05",)
    display_name = "Fake"
    dialect = "postgres"
    default_port = 6543
    capabilities = DatabaseCapabilities(
        network_proxy=False,
        simple_query=False,
        prepared_statements=False,
        named_portals=False,
        transaction_state=False,
        impact_estimation=False,
        tls_termination=False,
        binary_parameter_oids=False,
    )

    async def estimate_rows(self, preview_query, options):
        return 7

    async def start_proxy(self, options):
        return None


def test_external_adapter_can_be_registered():
    adapter = FakeAdapter()
    register_adapter(adapter, replace=True)

    assert get_adapter("test-fake-v05") is adapter
    assert get_adapter("test-fake-alias-v05") is adapter