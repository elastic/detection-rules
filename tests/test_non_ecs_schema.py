# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test non-ecs-schema.json for data integrity and consistency."""

import unittest
from collections import defaultdict

from detection_rules.ecs import flatten, get_non_ecs_schema, get_schema


class TestNonEcsSchema(unittest.TestCase):
    """Test the non-ecs-schema.json file for data quality and integrity."""

    VALID_ES_TYPES = frozenset(
        {
            "keyword",
            "text",
            "long",
            "integer",
            "short",
            "byte",
            "double",
            "float",
            "half_float",
            "scaled_float",
            "boolean",
            "date",
            "ip",
            "geo_point",
            "geo_shape",
            "binary",
            "object",
            "nested",
            "flattened",
            "wildcard",
            "match_only_text",
            "constant_keyword",
        }
    )

    @classmethod
    def setUpClass(cls):
        cls.non_ecs_schema = get_non_ecs_schema()

    def test_valid_json_structure(self):
        """Ensure the non-ecs-schema.json loads and has the expected top-level structure."""
        self.assertIsInstance(self.non_ecs_schema, dict, "non-ecs-schema.json should be a JSON object")
        self.assertGreater(len(self.non_ecs_schema), 0, "non-ecs-schema.json should not be empty")

        for index_pattern, fields in self.non_ecs_schema.items():
            self.assertIsInstance(
                index_pattern,
                str,
                f"Index pattern key should be a string, got {type(index_pattern)}",
            )
            self.assertIsInstance(
                fields,
                dict,
                f"Fields for index pattern '{index_pattern}' should be a dict, got {type(fields)}",
            )

    def test_no_duplicate_fields_within_index(self):
        """Ensure no index pattern contains duplicate flattened field names."""
        duplicates = {}

        for index_pattern, fields in self.non_ecs_schema.items():
            flattened = flatten(fields)
            field_names = list(flattened.keys())
            seen = set()
            dupes = set()

            for field_name in field_names:
                if field_name in seen:
                    dupes.add(field_name)
                seen.add(field_name)

            if dupes:
                duplicates[index_pattern] = sorted(dupes)

        if duplicates:
            err_lines = [f"  {idx}: {', '.join(dupe_fields)}" for idx, dupe_fields in duplicates.items()]
            self.fail("Duplicate fields found within index patterns:\n" + "\n".join(err_lines))

    def test_no_conflicting_field_types_across_indices(self):
        """Ensure the same field name does not have conflicting types across different index patterns."""
        field_type_map = defaultdict(dict)

        for index_pattern, fields in self.non_ecs_schema.items():
            flattened = flatten(fields)
            for field_name, field_type in flattened.items():
                field_type_map[field_name][index_pattern] = field_type

        conflicts = {}
        for field_name, index_types in field_type_map.items():
            unique_types = set(index_types.values())
            if len(unique_types) > 1:
                conflicts[field_name] = dict(index_types)

        if conflicts:
            err_lines = []
            for field_name, index_types in sorted(conflicts.items()):
                type_details = ", ".join(f"{idx}={t}" for idx, t in index_types.items())
                err_lines.append(f"  {field_name}: {type_details}")
            self.fail("Fields with conflicting types across index patterns:\n" + "\n".join(err_lines))

    def test_valid_field_types(self):
        """Validate that all field type values are valid Elasticsearch field types."""
        invalid = []

        for index_pattern, fields in self.non_ecs_schema.items():
            flattened = flatten(fields)
            for field_name, field_type in flattened.items():
                if field_type not in self.VALID_ES_TYPES:
                    invalid.append(f"  {index_pattern} -> {field_name}: '{field_type}'")

        if invalid:
            self.fail(
                "Invalid Elasticsearch field types found:\n"
                + "\n".join(invalid)
                + "\n\nValid types: "
                + ", ".join(sorted(self.VALID_ES_TYPES))
            )

    def test_fields_not_in_ecs(self):
        """Verify that fields in non-ecs-schema.json are not already present in the ECS flat schema."""
        ecs_schema = get_schema()
        overlapping = []

        for index_pattern, fields in self.non_ecs_schema.items():
            flattened = flatten(fields)
            overlapping.extend(
                f"  {index_pattern} -> {field_name}" for field_name in flattened if field_name in ecs_schema
            )

        if overlapping:
            self.fail(
                "The following fields in non-ecs-schema.json are already present in the ECS schema "
                "and should be removed to prevent redundancy:\n" + "\n".join(overlapping)
            )

    def test_no_empty_index_patterns(self):
        """Ensure no index pattern has an empty field mapping."""
        empty = [idx for idx, fields in self.non_ecs_schema.items() if not fields]

        if empty:
            self.fail("Empty index patterns found (no fields defined): " + ", ".join(empty))
