# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Keep content-exposure promotion scoped and preserve the catch-all migration path."""

import tomllib
import unittest
from pathlib import Path

import kql


class TestContentExposurePromotion(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        directory = Path(__file__).parents[1] / "rules/integrations/endpoint"
        cls.rule = tomllib.loads((directory / "elastic_endpoint_security_content_exposure.toml").read_text())["rule"]
        catch_all = tomllib.loads((directory / "elastic_endpoint_security.toml").read_text())["rule"]
        cls.matches = staticmethod(kql.get_evaluator(cls.rule["query"]))
        cls.catch_all_matches = staticmethod(kql.get_evaluator(catch_all["query"]))

    def test_three_stages_remain_eligible_for_either_promotion_strategy(self) -> None:
        for stage in ("input", "submission", "persistence"):
            with self.subTest(stage=stage):
                event = {
                    "event": {"kind": "alert", "module": "endpoint", "code": "content_exposure"},
                    "Endpoint": {"agent_exposure": {"stage": stage}},
                }
                self.assertTrue(self.matches(event))
                self.assertTrue(self.catch_all_matches(event))
        # Enabling the dedicated rule is an explicit switch from the catch-all strategy.
        self.assertFalse(self.rule["enabled"])

    def test_other_protections_and_raw_findings_are_not_promoted(self) -> None:
        for override in (
            {"code": "malicious_file"},
            {"code": "behavior"},
            {"kind": "event"},
            {"module": "endgame"},
            {"module": ["endpoint", "endgame"]},
            {"module": "other"},
        ):
            with self.subTest(override=override):
                event = {"kind": "alert", "module": "endpoint", "code": "content_exposure"} | override
                self.assertFalse(self.matches({"event": event}))

    def test_ordinary_defend_alerts_keep_catch_all_coverage(self) -> None:
        for code in ("malicious_file", "behavior", "memory_signature", "ransomware"):
            with self.subTest(code=code):
                self.assertTrue(
                    self.catch_all_matches({"event": {"kind": "alert", "module": "endpoint", "code": code}})
                )
