# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import time
import unittest

from elasticsearch import BadRequestError
from elasticsearch import ConnectionError as ESConnectionError

from detection_rules.misc import get_default_config, getdefault
from detection_rules.remote_validation import RemoteConnector
from detection_rules.rule_validators import ESQLValidator

from .base import BaseRuleTest


@unittest.skipIf(get_default_config() is None, "Skipping remote validation due to missing config")
@unittest.skipIf(
    not getdefault("remote_esql_validation")(), "Skipping remote validation because remote_esql_validation is False"
)
class TestRemoteRules(BaseRuleTest):
    """Test rules against a remote Elastic stack instance."""

    def test_esql_rules(self):
        """Test all ES|QL rules against a cluster."""

        esql_rules = [r for r in self.all_rules if r.contents.data.type == "esql"]

        print("ESQL rules loaded:", len(esql_rules))

        if not esql_rules:
            return

        remote_connector = RemoteConnector()
        if not remote_connector.es_client or not remote_connector.kibana_client:
            self.skipTest("Skipping remote validation due to missing client")

        # Retrieve verbosity level from pytest
        verbosity: int = int(self._outcome.result.config.get_verbosity())  # type: ignore[reportIncompatibleMethodOverride]

        failed_count = 0
        fail_list: list[str] = []
        max_retries = 3
        for r in esql_rules:
            print()
            retry_count = 0
            while retry_count < max_retries:
                try:
                    validator = ESQLValidator(r.contents.data.query)  # type: ignore[reportIncompatibleMethodOverride]
                    _ = validator.remote_validate_rule_contents(
                        remote_connector.kibana_client, remote_connector.es_client, r.contents, verbosity
                    )
                    break
                except (ValueError, BadRequestError) as e:
                    print(f"FAILURE: {e}")
                    fail_list.append(f"FAILURE: {e}")
                    failed_count += 1
                    break
                except ESConnectionError as e:
                    retry_count += 1
                    print(f"Connection error: {e}. Retrying {retry_count}/{max_retries}...")
                    time.sleep(30)
                    if retry_count == max_retries:
                        print(f"FAILURE: {e} after {max_retries} retries")
                        fail_list.append(f"FAILURE: {e} after {max_retries} retries")
                        failed_count += 1

        print(f"Total rules: {len(esql_rules)}")
        print(f"Failed rules: {failed_count}")

        if failed_count > 0:
            self.fail(f"Found {failed_count} invalid rules")
