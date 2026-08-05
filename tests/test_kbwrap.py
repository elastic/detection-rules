"""Tests for Kibana command wrappers."""

import inspect
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import click

from detection_rules.kbwrap import _enable_after_delay, _force_disabled_import, kibana_import_rules
from detection_rules.misc import ClientError


class TestForceDisabledImport(unittest.TestCase):
    """Resolving which rules to re-enable after a delayed import."""

    def test_resolves_intended_state_from_payload_and_kibana(self) -> None:
        """The intended state comes from `enabled` when set, otherwise from what Kibana would have applied."""
        rule_dicts = [
            {"rule_id": "explicit-enabled", "enabled": True},
            {"rule_id": "explicit-disabled", "enabled": False},
            {"rule_id": "omitted-deployed-enabled"},
            {"rule_id": "omitted-deployed-disabled"},
            {"rule_id": "omitted-new-rule"},
        ]
        deployed = [
            {"rule_id": "omitted-deployed-enabled", "enabled": True},
            {"rule_id": "omitted-deployed-disabled", "enabled": False},
            # omitted-new-rule is absent: Kibana returns a per-object error for unknown rule_ids
            {"error": {"status_code": 404, "message": "not found"}},
        ]

        with patch("detection_rules.kbwrap.RuleResource.export_rules", return_value=deployed) as export_rules:
            rule_ids_to_enable = _force_disabled_import(rule_dicts)

        self.assertCountEqual(export_rules.call_args.args[0], [rule_dict["rule_id"] for rule_dict in rule_dicts])
        self.assertEqual(rule_ids_to_enable, {"explicit-enabled", "omitted-deployed-enabled", "omitted-new-rule"})
        # Every rule is imported as disabled regardless of its intended state
        self.assertTrue(all(rule_dict["enabled"] is False for rule_dict in rule_dicts))

    def test_skips_kibana_lookup_when_every_rule_is_explicit(self) -> None:
        """No deployed state is needed when all payloads set `enabled`."""
        rule_dicts = [{"rule_id": "a", "enabled": True}, {"rule_id": "b", "enabled": False}]

        with patch("detection_rules.kbwrap.RuleResource.export_rules") as export_rules:
            rule_ids_to_enable = _force_disabled_import(rule_dicts)

        export_rules.assert_not_called()
        self.assertEqual(rule_ids_to_enable, {"a"})


class TestEnableAfterDelay(unittest.TestCase):
    """Waiting out the delay before bulk enabling."""

    @staticmethod
    def _kibana() -> MagicMock:
        kibana = MagicMock()
        kibana.__enter__.return_value = kibana
        return kibana

    def test_waits_then_bulk_enables(self) -> None:
        """The delay is honored and the rules are enabled by their Kibana object ids."""
        response = {"attributes": {"summary": {"succeeded": 2, "failed": 0}, "errors": []}}

        with (
            patch("detection_rules.kbwrap.RuleResource.bulk_action", return_value=response) as bulk_action,
            patch("detection_rules.kbwrap.time.sleep") as sleep,
        ):
            _enable_after_delay(click.Context(kibana_import_rules), self._kibana(), ["1", "3"], 30)

        sleep.assert_called_once_with(30)
        bulk_action.assert_called_once_with("enable", rule_ids=["1", "3"], error=False)

    def test_raises_when_any_rule_fails_to_enable(self) -> None:
        """A partial enable failure surfaces as a client error rather than a silent success."""
        response = {
            "attributes": {
                "summary": {"succeeded": 0, "failed": 1},
                "errors": [{"status_code": 500, "message": "failed", "rules": [{"id": "1"}]}],
            }
        }

        with (
            patch("detection_rules.kbwrap.RuleResource.bulk_action", return_value=response),
            patch("detection_rules.kbwrap.time.sleep"),
            self.assertRaisesRegex(ClientError, r"1 imported rule\(s\) failed to enable"),
        ):
            _enable_after_delay(click.Context(kibana_import_rules), self._kibana(), ["1"], 30)


class TestKibanaImportRulesEnableDelay(unittest.TestCase):
    """`--enable-delay` wiring within the import command."""

    def test_imports_disabled_then_enables_by_object_id(self) -> None:
        """Rules are imported disabled and re-enabled using the ids returned by the import."""
        # Bypass the click option decorators; rules are passed in directly instead of loaded from disk
        implementation = inspect.unwrap(kibana_import_rules.callback)
        kibana = MagicMock()
        kibana.__enter__.return_value = kibana
        rules = [
            SimpleNamespace(contents=SimpleNamespace(to_api_format=lambda: {"rule_id": "wanted", "enabled": True})),
            SimpleNamespace(contents=SimpleNamespace(to_api_format=lambda: {"rule_id": "unwanted", "enabled": False})),
        ]
        import_response = {"errors": []}
        import_results = [{"id": "1", "rule_id": "wanted"}, {"id": "2", "rule_id": "unwanted"}]

        with (
            patch("detection_rules.kbwrap.GenericCollection.default") as generic_collection,
            patch(
                "detection_rules.kbwrap.RuleResource.import_rules",
                return_value=(import_response, ["wanted", "unwanted"], import_results),
            ) as import_rules,
            patch(
                "detection_rules.kbwrap.RuleResource.bulk_action",
                return_value={"attributes": {"summary": {"succeeded": 1, "failed": 0}, "errors": []}},
            ) as bulk_action,
            patch("detection_rules.kbwrap.time.sleep") as sleep,
        ):
            generic_collection.return_value.items_matching.return_value = []
            result = implementation(
                click.Context(kibana_import_rules, obj={"kibana": kibana}),
                rules,
                overwrite=False,
                overwrite_exceptions=False,
                overwrite_action_connectors=False,
                enable_delay=30,
            )

        self.assertEqual(result, (import_response, import_results))
        self.assertEqual(
            import_rules.call_args.args[0],
            [{"rule_id": "wanted", "enabled": False}, {"rule_id": "unwanted", "enabled": False}],
        )
        sleep.assert_called_once_with(30)
        bulk_action.assert_called_once_with("enable", rule_ids=["1"], error=False)

    def test_option_requires_a_positive_delay(self) -> None:
        """The safeguard cannot be invoked without a wait."""
        ctx = kibana_import_rules.make_context("import-rules", ["--enable-delay", "30"])
        self.assertEqual(ctx.params["enable_delay"], 30)

        for value in ("0", "-5"):
            with self.assertRaises(click.exceptions.UsageError):
                _ = kibana_import_rules.make_context("import-rules", ["--enable-delay", value])
