# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Tests for GitHub gist helpers."""

import unittest

from detection_rules.ghwrap import batch_gist_files


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
