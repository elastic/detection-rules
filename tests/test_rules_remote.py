# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import unittest

from detection_rules.misc import get_default_config, get_elasticsearch_client, get_kibana_client, getdefault
from detection_rules.rule_validators import validate_esql_rule

from .base import BaseRuleTest


@unittest.skipIf(get_default_config() is None, "Skipping remote validation due to missing config")
class TestRemoteRules(BaseRuleTest):
    """Test rules against a remote Elastic stack instance."""

    def test_esql_rules(self):
        """Test all ES|QL rules against a cluster."""

        esql_rules = [r for r in self.all_rules if r.contents.data.type == "esql"]

        print("ESQL rules loaded:", len(esql_rules))

        if not esql_rules:
            return

        kibana_client = get_kibana_client(
            api_key=getdefault("api_key")(),
            cloud_id=getdefault("cloud_id")(),
            kibana_url=getdefault("kibana_url")(),
            space=getdefault("space")(),
            ignore_ssl_errors=getdefault("ignore_ssl_errors")(),
        )

        elastic_client = get_elasticsearch_client(
            api_key=getdefault("api_key")(),
            cloud_id=getdefault("cloud_id")(),
            elasticsearch_url=getdefault("elasticsearch_url")(),
            ignore_ssl_errors=getdefault("ignore_ssl_errors")(),
        )

        failed_count = 0
        fail_list = []

        for r in esql_rules:
            print()
            try:
                validate_esql_rule(kibana_client, elastic_client, r.contents)
            except Exception as e:
                print(f"FAILURE: {e}")
                fail_list.append(f"FAILURE: {e}")
                failed_count += 1

        print(f"Total rules: {len(esql_rules)}")
        print(f"Failed rules: {failed_count}")

        if failed_count > 0:
            self.fail(f"Found {failed_count} invalid rules")
