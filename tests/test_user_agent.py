# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Tests for the optional Kibana User-Agent telemetry header."""

import os
import unittest

from kibana.connector import USER_AGENT_DISABLE_ENV, Kibana


class TestUserAgent(unittest.TestCase):
    """Test that the custom User-Agent is present by default and absent when disabled."""

    def setUp(self) -> None:
        self._prev = os.environ.pop(USER_AGENT_DISABLE_ENV, None)

    def tearDown(self) -> None:
        os.environ.pop(USER_AGENT_DISABLE_ENV, None)
        if self._prev is not None:
            os.environ[USER_AGENT_DISABLE_ENV] = self._prev

    def test_user_agent_present_by_default(self) -> None:
        """A constructed client carries the detection-rules User-Agent."""
        client = Kibana(kibana_url="https://example.com", api_key="abc")
        ua = client.session.headers.get("User-Agent")
        assert ua is not None
        assert "detection-rules" in ua

    def test_user_agent_absent_when_disabled(self) -> None:
        """Setting the disable env var suppresses the custom User-Agent."""
        os.environ[USER_AGENT_DISABLE_ENV] = "true"
        client = Kibana(kibana_url="https://example.com", api_key="abc")
        ua = client.session.headers.get("User-Agent")
        assert ua is None or ua.startswith("python-requests/")


if __name__ == "__main__":
    unittest.main()
