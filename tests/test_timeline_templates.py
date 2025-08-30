# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Tests for loading timeline template TOML files."""

import unittest

from detection_rules.generic_loader import GenericCollection
from detection_rules.timeline import TOMLTimelineTemplateContents


class TestTimelineTemplates(unittest.TestCase):
    """Unit tests for timeline templates loading and metadata."""

    def test_load_timeline_template(self) -> None:
        """Ensure timeline templates load and expose expected metadata."""

        collection = GenericCollection.default()
        timelines = [i for i in collection.items if isinstance(i.contents, TOMLTimelineTemplateContents)]
        self.assertTrue(timelines, "No timeline templates loaded")
        tt = timelines[0]
        self.assertEqual(
            tt.contents.metadata.timeline_template_id,
            tt.contents.timeline["templateTimelineId"],
        )
        self.assertEqual(
            tt.contents.metadata.timeline_template_title,
            tt.contents.timeline["title"],
        )
