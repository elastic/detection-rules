# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Tests for GitHub gist helpers."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import MagicMock, patch

from detection_rules.ghwrap import batch_gist_files, update_gist


class TestGistBatching(unittest.TestCase):
    """Keep gist PATCH payloads within GitHub file limits."""

    def test_batch_mapping_splits_evenly(self) -> None:
        mapping = {f"file-{index}.json": {} for index in range(5)}
        batches = batch_gist_files(mapping, 2)
        self.assertEqual(len(batches), 3)
        self.assertEqual(sum(len(batch) for batch in batches), 5)
        self.assertEqual(len(batches[-1]), 1)

    def test_batch_mapping_empty(self) -> None:
        self.assertEqual(batch_gist_files({}, 50), [])

    def test_update_gist_purges_with_null_then_uploads_in_chunks(self) -> None:
        stale_names = [f"stale-{index}.json" for index in range(5)]
        keep_names = [
            "Elastic-detection-rules-all.json",
            "Elastic-detection-rules-platforms.json",
            "Elastic-detection-rules-extra.json",
        ]
        existing = {name: {"raw_url": "https://example.invalid"} for name in [*stale_names, keep_names[0]]}
        get_response = MagicMock()
        get_response.json.return_value = {"files": existing}
        patch_response = MagicMock()
        patch_response.json.return_value = {
            "files": {name: {"raw_url": "https://example.invalid"} for name in keep_names}
        }

        with (
            TemporaryDirectory() as tmp,
            patch("detection_rules.ghwrap.requests.get", return_value=get_response) as get_mock,
            patch("detection_rules.ghwrap.requests.patch", return_value=patch_response) as patch_mock,
            patch("detection_rules.ghwrap._GIST_PATCH_FILE_LIMIT", 2),
        ):
            file_map = {}
            directory = Path(tmp)
            for name in keep_names:
                path = directory / name
                path.write_text(f'{{"name": "{name}"}}')
                file_map[path] = path.read_text()
            update_gist("x", file_map, "ATT&CK Navigator layer files.", "gist-id", pre_purge=True)

        get_mock.assert_called_once()
        payloads: list[dict[str, Any]] = [call.kwargs["json"]["files"] for call in patch_mock.call_args_list]
        delete_payloads = [files for files in payloads if files and all(value is None for value in files.values())]
        upload_payloads = [files for files in payloads if files not in delete_payloads]

        self.assertEqual(sum(len(files) for files in delete_payloads), 5)
        self.assertTrue(all(len(files) <= 2 for files in [*delete_payloads, *upload_payloads]))
        self.assertEqual(sorted(name for files in delete_payloads for name in files), sorted(stale_names))
        self.assertTrue(all(value is None for files in delete_payloads for value in files.values()))
        self.assertEqual(len(upload_payloads), 2)
        uploaded = {name: body["content"] for files in upload_payloads for name, body in files.items()}
        self.assertEqual(set(uploaded), set(keep_names))
        self.assertNotIn(keep_names[0], {name for files in delete_payloads for name in files})
