# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Tests for ATT&CK navigator layer generation."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from detection_rules.navigator import (
    PUBLISHED_NAVIGATOR_LAYERS,
    NavigatorBuilder,
    navigator_layer_label,
    navigator_layer_path,
    navigator_tag_layer_key,
    sanitize_navigator_name,
    select_navigator_gist_files,
)


class TestNavigatorNames(unittest.TestCase):
    """Ensure navigator layer filenames stay on a single path component."""

    def test_sanitize_replaces_path_separators(self) -> None:
        self.assertEqual(
            sanitize_navigator_name("tags-lnk/shortcut-abuse"),
            "tags-lnk-shortcut-abuse",
        )
        self.assertEqual(
            sanitize_navigator_name("indexes-logs-endpoint.events.*"),
            "indexes-logs-endpoint.events.WILDCARD",
        )

    def test_save_slash_tag_does_not_create_nested_directory(self) -> None:
        builder = NavigatorBuilder([])
        builder.layers["tags"]["lnk/shortcut-abuse"]["defense evasion"]["T1204"] = {
            "metadata": [{"name": "test", "value": "id"}],
            "links": [{"label": "repo", "url": "https://github.com/elastic/detection-rules"}],
        }
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            path, _built = builder.save_layer("tags", directory, layer_key="lnk/shortcut-abuse", verbose=False)
            self.assertEqual(path.parent, directory)
            self.assertEqual(path.name, "Elastic-detection-rules-tags-lnk-shortcut-abuse.json")
            self.assertTrue(path.is_file())

    def test_save_all_raises_on_sanitized_filename_collision(self) -> None:
        builder = NavigatorBuilder([])
        technique = {
            "metadata": [{"name": "test", "value": "id"}],
            "links": [{"label": "repo", "url": "https://github.com/elastic/detection-rules"}],
        }
        builder.layers["tags"]["lnk/shortcut-abuse"]["defense evasion"]["T1204"] = technique
        builder.layers["tags"]["lnk-shortcut-abuse"]["defense evasion"]["T1204"] = {
            "metadata": [{"name": "other", "value": "id2"}],
            "links": [{"label": "repo", "url": "https://github.com/elastic/detection-rules"}],
        }
        with TemporaryDirectory() as tmp, self.assertRaises(ValueError) as ctx:
            builder.save_all(Path(tmp), verbose=False)
        self.assertIn("collide after sanitization", str(ctx.exception))
        self.assertIn("lnk-shortcut-abuse.json", str(ctx.exception))

    def test_save_dotted_index_keeps_full_name(self) -> None:
        builder = NavigatorBuilder([])
        technique = {
            "metadata": [{"name": "test", "value": "id"}],
            "links": [{"label": "repo", "url": "https://github.com/elastic/detection-rules"}],
        }
        builder.layers["indexes"]["logs-endpoint.events.*"]["defense evasion"]["T1204"] = technique
        builder.layers["indexes"]["logs-endpoint.events.process-*"]["defense evasion"]["T1204"] = {
            "metadata": [{"name": "other", "value": "id2"}],
            "links": [{"label": "repo", "url": "https://github.com/elastic/detection-rules"}],
        }
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            paths = builder.save_all(directory, verbose=False)
            names = {path.name for path in paths}
            wildcard = "Elastic-detection-rules-indexes-logs-endpoint.events.WILDCARD.json"
            process = "Elastic-detection-rules-indexes-logs-endpoint.events.process-WILDCARD.json"
            self.assertEqual(names, {wildcard, process})
            self.assertTrue((directory / wildcard).is_file())
            self.assertTrue((directory / process).is_file())

    def test_layer_path_appends_json_after_dots(self) -> None:
        dotted = "Elastic-detection-rules-indexes-logs-endpoint.events.WILDCARD"
        with TemporaryDirectory() as tmp:
            path = navigator_layer_path(Path(tmp), dotted)
            self.assertEqual(path.name, f"{dotted}.json")
            self.assertNotEqual(Path(dotted).with_suffix(".json").name, path.name)

    def test_layer_label_keeps_dotted_name(self) -> None:
        name = "Elastic-detection-rules-indexes-logs-endpoint.events.WILDCARD.json"
        self.assertEqual(
            navigator_layer_label(name),
            "Elastic-detection-rules-indexes-logs-endpoint.events.WILDCARD",
        )
        self.assertNotEqual(name.split(".", maxsplit=1)[0], navigator_layer_label(name))

    def test_tag_layer_keys_stay_distinct_until_filename_sanitize(self) -> None:
        slash_key = navigator_tag_layer_key("Tactic: LNK/Shortcut Abuse")
        dash_key = navigator_tag_layer_key("Tactic: LNK-Shortcut Abuse")
        self.assertEqual(slash_key, "lnk/shortcut-abuse")
        self.assertEqual(dash_key, "lnk-shortcut-abuse")
        self.assertNotEqual(slash_key, dash_key)
        self.assertEqual(sanitize_navigator_name(slash_key), sanitize_navigator_name(dash_key))

        star_key = navigator_tag_layer_key("Tactic: Foo*")
        wildcard_key = navigator_tag_layer_key("Tactic: FooWILDCARD")
        self.assertEqual(star_key, "foo*")
        self.assertEqual(wildcard_key, "foowildcard")
        self.assertNotEqual(star_key, wildcard_key)
        self.assertEqual(sanitize_navigator_name(star_key), "fooWILDCARD")

    def test_save_all_can_limit_to_published_layers(self) -> None:
        builder = NavigatorBuilder([])
        technique = {
            "metadata": [{"name": "test", "value": "id"}],
            "links": [{"label": "repo", "url": "https://github.com/elastic/detection-rules"}],
        }
        builder.layers["all"]["defense evasion"]["T1204"] = technique
        builder.layers["platforms"]["defense evasion"]["T1204"] = technique
        builder.layers["tags"]["aws"]["defense evasion"]["T1204"] = technique
        builder.layers["indexes"]["logs-aws.cloudtrail-*"]["defense evasion"]["T1204"] = technique
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            paths = builder.save_all(directory, verbose=False, layer_names=PUBLISHED_NAVIGATOR_LAYERS)
            names = {path.name for path in paths}
            self.assertEqual(
                names,
                {
                    "Elastic-detection-rules-all.json",
                    "Elastic-detection-rules-platforms.json",
                },
            )
            self.assertEqual(list(directory.glob("*tags*")), [])
            self.assertEqual(list(directory.glob("*indexes*")), [])

    def test_select_navigator_gist_files_ignores_tag_and_index_layers(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            all_layer = directory / "Elastic-detection-rules-all.json"
            platforms_layer = directory / "Elastic-detection-rules-platforms.json"
            (directory / "Elastic-detection-rules-tags-aws.json").write_text("{}")
            (directory / "Elastic-detection-rules-indexes-logs-aws.json").write_text("{}")
            all_layer.write_text("{}")
            platforms_layer.write_text("{}")
            selected = select_navigator_gist_files(directory)
            self.assertEqual({path.name for path in selected}, {all_layer.name, platforms_layer.name})

    def test_select_navigator_gist_files_requires_published_layers(self) -> None:
        with TemporaryDirectory() as tmp, self.assertRaises(FileNotFoundError) as ctx:
            select_navigator_gist_files(Path(tmp))
        self.assertIn("Elastic-detection-rules-all.json", str(ctx.exception))
        self.assertIn("Elastic-detection-rules-platforms.json", str(ctx.exception))
