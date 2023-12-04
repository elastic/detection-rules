# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from contextlib import nullcontext as does_not_raise
from copy import deepcopy
from pathlib import Path

import pytest

from esql.errors import ESQLSyntaxError, ESQLSemanticError
from detection_rules.rule_loader import RuleCollection
from detection_rules.utils import get_path, load_rule_contents

from .base import BaseRuleTest


class TestESQLRules(BaseRuleTest):
    """Test ESQL Rules."""

    def run_esql_test(self, esql_query, expectation, message):
        """Test that the query validation is working correctly."""
        rc = RuleCollection()
        file_path = Path(get_path("tests", "data", "command_control_dummy_production_rule.toml"))
        original_production_rule = load_rule_contents(file_path)
        # Test that a ValidationError is raised if the query doesn't match the schema
        production_rule = deepcopy(original_production_rule)[0]
        if esql_query:
            production_rule["rule"]["query"] = esql_query
        expectation.match_expr = message
        with expectation:
            rc.load_dict(production_rule)

    def test_esql_queries(self):
        """Test ESQL queries."""
        test_cases = [
            # invalid queries
            # `wheres` should be `where`
            ('from .ds-logs-endpoint.events.process-default-* | wheres process.name like "Microsoft*"',
             pytest.raises(ESQLSyntaxError), r"ESQL syntax error"),

            # `process.names` should be `process.name`
            ('from .ds-logs-endpoint.events.process-default-* [metadata _id, _version, _index] | where process.names like "Microsoft*"',  # noqa: E501
             pytest.raises(ESQLSemanticError), r"ESQL semantic error: Invalid field: process.names"),

            # Missing `[metadata _id, _version, _index]` without stats
            ('from .ds-logs-endpoint.events.process-default-* | where process.name like "Microsoft*"',
             pytest.raises(ESQLSemanticError), r"ESQL semantic error: Missing metadata for ES|QL query with no stats command"),  # noqa: E501

            # returns 0 because count on non-forwarded field process.parent.name
            # ('from .ds-logs-endpoint.events.process-default-* | where process.name like "Microsoft*" | keep host.os.type | STATS process_count = COUNT(process.parent.name)',  # noqa: E501
            # pytest.raises(ESQLSemanticError), r"ESQL semantic error"),

            # aggregation function AVG on text\keyword field type
            #   ('from .ds-logs-endpoint.events.process-default-* | where process.name like "Microsoft*" | keep host.os.type | STATS process_count = AVG(host.os.type)',  # noqa: E501
            #   pytest.raises(ESQLSemanticError), r"ESQL semantic error"),

            #  Overwriting text/keyword ECS/integration field with different type from function or aggregation operator
            #   ('from .ds-logs-endpoint.events.process-default-* | where process.name like "Microsoft*" | keep host.os.type | STATS process.name = COUNT(process.name),  # noqa: E501
            #   pytest.raises(ESQLSemanticError), r"ESQL semantic error"),

            # valid queries
            # base query within test rule
            ('', does_not_raise(), None),

            # author defined field supported
            #  | eval process_path = replace(process.executable, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9\.\-\_\$]+\\""", "C:\\\\users\\\\user\\\\")  # noqa: E501
        ]
        for esql_query, expectation, message in test_cases:
            self.run_esql_test(esql_query, expectation, message)
