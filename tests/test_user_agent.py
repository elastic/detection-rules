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
        self.assertIsNotNone(ua)
        self.assertIn("detection-rules", ua)

    def test_user_agent_absent_when_disabled(self) -> None:
        """Setting the disable env var suppresses the custom User-Agent."""
        os.environ[USER_AGENT_DISABLE_ENV] = "True"
        client = Kibana(kibana_url="https://example.com", api_key="abc")
        ua = client.session.headers.get("User-Agent")
        self.assertTrue(ua is None or ua.startswith("python-requests/"))

    def test_user_agent_override_is_used(self) -> None:
        """An explicit ``user_agent`` argument is set verbatim on the session."""
        client = Kibana(kibana_url="https://example.com", api_key="abc", user_agent="custom-agent/1.2.3")
        ua = client.session.headers.get("User-Agent")
        self.assertEqual(ua, "custom-agent/1.2.3")

    def test_disable_env_takes_precedence_over_override(self) -> None:
        """When disabled, an explicit ``user_agent`` override is ignored."""
        os.environ[USER_AGENT_DISABLE_ENV] = "True"
        client = Kibana(kibana_url="https://example.com", api_key="abc", user_agent="custom-agent/1.2.3")
        ua = client.session.headers.get("User-Agent")
        self.assertTrue(ua is None or ua.startswith("python-requests/"))


if __name__ == "__main__":
    unittest.main()
