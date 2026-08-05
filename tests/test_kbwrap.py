"""Tests for Kibana command wrappers."""

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import click

from detection_rules.kbwrap import kibana_import_rules
from detection_rules.misc import ClientError


class TestKibanaImportRulesEnableDelay(unittest.TestCase):
    """The delayed enable safeguard preserves intended rule state."""

    @staticmethod
    def _invoke_import_rules(
        rules: list[SimpleNamespace],
        kibana: MagicMock,
        enable_delay: int = 30,
    ) -> tuple[dict[str, object], list[dict[str, str]]]:
        """Invoke the undecorated import command with test doubles."""
        callback = kibana_import_rules.callback
        assert callback is not None
        implementation = callback.__wrapped__.__wrapped__
        ctx = click.Context(kibana_import_rules, obj={"kibana": kibana})
        return implementation(
            ctx,
            rules,
            overwrite=False,
            overwrite_exceptions=False,
            overwrite_action_connectors=False,
            enable_delay=enable_delay,
        )

    @staticmethod
    def _rule(payload: dict[str, object]) -> SimpleNamespace:
        """Create a minimal rule accepted by the import command."""
        return SimpleNamespace(contents=SimpleNamespace(to_api_format=lambda: payload.copy()))

    def test_enable_delay_preserves_explicit_and_existing_enabled_states(self) -> None:
        """Only rules intended to be enabled are enabled after the delay."""
        kibana = MagicMock()
        kibana.__enter__.return_value = kibana
        rules = [
            self._rule({"rule_id": "explicit-enabled", "enabled": True}),
            self._rule({"rule_id": "explicit-disabled", "enabled": False}),
            self._rule({"rule_id": "new-rule"}),
            self._rule({"rule_id": "existing-disabled"}),
        ]
        import_response = {"errors": []}
        import_results = [
            {"id": "1", "rule_id": "explicit-enabled"},
            {"id": "2", "rule_id": "explicit-disabled"},
            {"id": "3", "rule_id": "new-rule"},
            {"id": "4", "rule_id": "existing-disabled"},
        ]

        with (
            patch("detection_rules.kbwrap.GenericCollection.default") as generic_collection,
            patch(
                "detection_rules.kbwrap.RuleResource.export_rules",
                return_value=[{"rule_id": "existing-disabled", "enabled": False}],
            ) as export_rules,
            patch(
                "detection_rules.kbwrap.RuleResource.import_rules",
                return_value=(import_response, [rule["rule_id"] for rule in import_results], import_results),
            ) as import_rules,
            patch(
                "detection_rules.kbwrap.RuleResource.bulk_action",
                return_value={"attributes": {"summary": {"succeeded": 2, "failed": 0}, "errors": []}},
            ) as bulk_action,
            patch("detection_rules.kbwrap.time.sleep") as sleep,
        ):
            generic_collection.return_value.items_matching.return_value = []
            result = self._invoke_import_rules(rules, kibana)

        self.assertEqual(result, (import_response, import_results))
        self.assertCountEqual(export_rules.call_args.args[0], [rule["rule_id"] for rule in import_results])
        self.assertEqual(
            import_rules.call_args.args[0],
            [
                {"rule_id": "explicit-enabled", "enabled": False},
                {"rule_id": "explicit-disabled", "enabled": False},
                {"rule_id": "new-rule", "enabled": False},
                {"rule_id": "existing-disabled", "enabled": False},
            ],
        )
        sleep.assert_called_once_with(30)
        bulk_action.assert_called_once_with("enable", rule_ids=["1", "3"], error=False)

    def test_enable_delay_fails_when_bulk_enable_has_failures(self) -> None:
        """A partial enable failure causes a non-zero command result."""
        kibana = MagicMock()
        kibana.__enter__.return_value = kibana
        rules = [self._rule({"rule_id": "explicit-enabled", "enabled": True})]

        with (
            patch("detection_rules.kbwrap.GenericCollection.default") as generic_collection,
            patch(
                "detection_rules.kbwrap.RuleResource.import_rules",
                return_value=({"errors": []}, ["explicit-enabled"], [{"id": "1", "rule_id": "explicit-enabled"}]),
            ),
            patch(
                "detection_rules.kbwrap.RuleResource.bulk_action",
                return_value={
                    "attributes": {
                        "summary": {"succeeded": 0, "failed": 1},
                        "errors": [{"status_code": 500, "message": "failed", "rules": [{"id": "1"}]}],
                    }
                },
            ),
            patch("detection_rules.kbwrap.time.sleep"),
            self.assertRaisesRegex(ClientError, "1 imported rule\\(s\\) failed to enable"),
        ):
            generic_collection.return_value.items_matching.return_value = []
            _ = self._invoke_import_rules(rules, kibana)

    def test_enable_delay_requires_a_positive_delay(self) -> None:
        """The safeguard cannot be invoked without a wait."""
        ctx = kibana_import_rules.make_context("import-rules", ["--enable-delay", "30"])
        self.assertEqual(ctx.params["enable_delay"], 30)

        for value in ("0", "-5"):
            with self.assertRaises(click.exceptions.UsageError):
                _ = kibana_import_rules.make_context("import-rules", ["--enable-delay", value])
