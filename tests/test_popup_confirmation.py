import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from sql_safety_proxy.confirmation import QueryContext
from sql_safety_proxy.popup_confirmation import PopupConfirmationProvider


class PopupProviderTests(unittest.TestCase):
    def test_confirm_runs_dialog_off_event_loop(self):
        provider = PopupConfirmationProvider()
        ctx = QueryContext(
            sql="DELETE FROM users;",
            classification=SimpleNamespace(
                risk="risky",
                statement_type="DELETE",
                reason="DELETE has no WHERE clause",
            ),
        )
        with patch.object(provider, "_show_dialog_serialized", return_value=False) as show:
            approved = asyncio.run(provider.confirm(ctx))
        self.assertFalse(approved)
        show.assert_called_once_with(ctx)

    def test_dialog_lock_exists_for_serialization(self):
        provider = PopupConfirmationProvider()
        self.assertIsNotNone(provider._dialog_lock)


if __name__ == "__main__":
    unittest.main()
