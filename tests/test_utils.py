# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test util time functions."""

import random
import time
import unittest
from typing import Any

from detection_rules.ecs import get_kql_schema
from detection_rules.eswrap import Events
from detection_rules.utils import cached, cached_method, clear_caches, clear_method_cache, normalize_timing_and_sort


class TestTimeUtils(unittest.TestCase):
    """Test util time functions."""

    @staticmethod
    def get_events(timestamp_field="@timestamp"):
        """Get test data."""
        date_formats = {
            "epoch_millis": lambda x: int(round(time.time(), 3) + x) * 1000,
            "epoch_second": lambda x: round(time.time()) + x,
            "unix_micros": lambda x: time.time() + x,
            "unix_millis": lambda x: round(time.time(), 3) + x,
            "strict_date_optional_time": lambda x: "2020-05-13T04:36:" + str(15 + x) + ".394Z",
        }

        def _get_data(func):
            data = [
                {timestamp_field: func(0), "foo": "bar", "id": 1},
                {timestamp_field: func(1), "foo": "bar", "id": 2},
                {timestamp_field: func(2), "foo": "bar", "id": 3},
                {timestamp_field: func(3), "foo": "bar", "id": 4},
                {timestamp_field: func(4), "foo": "bar", "id": 5},
                {timestamp_field: func(5), "foo": "bar", "id": 6},
            ]
            random.shuffle(data)
            return data

        return {fmt: _get_data(func) for fmt, func in date_formats.items()}

    def assert_sort(self, normalized_events, date_format):
        """Assert normalize and sort."""
        order = [e["id"] for e in normalized_events]
        self.assertListEqual([1, 2, 3, 4, 5, 6], order, f"Sorting failed for date_format: {date_format}")

    def test_time_normalize(self):
        """Test normalize_timing_from_date_format."""
        events_data = self.get_events()
        for date_format, events in events_data.items():
            normalized = normalize_timing_and_sort(events)
            self.assert_sort(normalized, date_format)

    def test_event_class_normalization(self):
        """Test that events are normalized properly within Events."""
        events_data = self.get_events()
        for date_format, events in events_data.items():
            normalized = Events({"winlogbeat": events})
            self.assert_sort(normalized.events["winlogbeat"], date_format)

    def test_schema_multifields(self):
        """Tests that schemas are loading multifields correctly."""
        schema = get_kql_schema(version="1.4.0")
        self.assertEqual(schema.get("process.name"), "keyword")
        self.assertEqual(schema.get("process.name.text"), "text")

    def test_caching(self):
        """Test that caching is working."""
        counter = 0

        @cached
        def increment(*args, **kwargs):
            nonlocal counter

            counter += 1
            return counter

        self.assertEqual(increment(), 1)
        self.assertEqual(increment(), 1)
        self.assertEqual(increment(), 1)

        self.assertEqual(increment(["hello", "world"]), 2)
        self.assertEqual(increment(["hello", "world"]), 2)
        self.assertEqual(increment(["hello", "world"]), 2)

        self.assertEqual(increment(), 1)
        self.assertEqual(increment(["hello", "world"]), 2)

        self.assertEqual(increment({"hello": [("world",)]}), 3)
        self.assertEqual(increment({"hello": [("world",)]}), 3)

        self.assertEqual(increment(), 1)
        self.assertEqual(increment(["hello", "world"]), 2)
        self.assertEqual(increment({"hello": [("world",)]}), 3)

        increment.clear()
        self.assertEqual(increment({"hello": [("world",)]}), 4)
        self.assertEqual(increment(["hello", "world"]), 5)
        self.assertEqual(increment(), 6)
        self.assertEqual(increment(None), 7)
        self.assertEqual(increment(1), 8)

    def test_cached_method_flushes_with_clear_caches(self):
        """Test that cached_method memoizes per instance and is invalidated by clear_caches()."""

        class Counter:
            def __init__(self) -> None:
                self.calls = 0

            @cached_method
            def compute(self, *_args: Any, **_kwargs: Any) -> int:
                self.calls += 1
                return self.calls

        first, second = Counter(), Counter()

        # memoized per instance and per argument set
        self.assertEqual(first.compute(), 1)
        self.assertEqual(first.compute(), 1)
        self.assertEqual(first.compute(["hello", "world"]), 2)
        self.assertEqual(first.compute(["hello", "world"]), 2)
        self.assertEqual(second.compute(), 1)

        # the auto-add schema retry path relies on clear_caches() to make every memoized derived
        # result reload, including ones stored on instances that outlive the flush
        clear_caches()
        self.assertEqual(first.compute(), 3)
        self.assertEqual(first.compute(["hello", "world"]), 4)
        self.assertEqual(first.compute(), 3)
        self.assertEqual(second.compute(), 2)

        # per-instance flush leaves other instances alone
        clear_method_cache(first)
        self.assertEqual(first.compute(), 5)
        self.assertEqual(second.compute(), 2)
