# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test fields in TOML [transform]."""
import copy
import unittest
from pathlib import Path
from textwrap import dedent

import pytoml

from detection_rules.devtools import guide_plugin_convert_
from detection_rules.rule import TOMLRule, TOMLRuleContents
from detection_rules.rule_loader import RuleCollection

RULES_DIR = Path(__file__).parent.parent / 'rules'


class TestGuideMarkdownPlugins(unittest.TestCase):
    """Test the Markdown plugin features within the investigation guide."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.osquery_patterns = [
            """!{osquery{"label":"Osquery - Retrieve DNS Cache","query":"SELECT * FROM dns_cache"}}""",
            """!{osquery{"label":"Osquery - Retrieve All Services","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services"}}""",  # noqa: E501
            """!{osquery{"label":"Osquery - Retrieve Services Running on User Accounts","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE NOT (user_account LIKE '%LocalSystem' OR user_account LIKE '%LocalService' OR user_account LIKE '%NetworkService' OR user_account == null)"}}""",  # noqa: E501
            """!{osquery{"label":"Retrieve Service Unisgned Executables with Virustotal Link","query":"SELECT concat('https://www.virustotal.com/gui/file/', sha1) AS VtLink, name, description, start_type, status, pid, services.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path = authenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != 'trusted'"}}""",  # noqa: E501
        ]

    @staticmethod
    def load_rule() -> TOMLRule:
        rc = RuleCollection()
        windows_rule = list(RULES_DIR.joinpath('windows').glob('*.toml'))[0]
        sample_rule = rc.load_file(windows_rule)
        return sample_rule

    def test_transform_guide_markdown_plugins(self) -> None:
        sample_rule = self.load_rule()
        rule_dict = sample_rule.contents.to_dict()
        osquery_toml = dedent("""
        [transform]
        [[transform.osquery]]
        label = "Osquery - Retrieve DNS Cache"
        query = "SELECT * FROM dns_cache"

        [[transform.osquery]]
        label = "Osquery - Retrieve All Services"
        query = "SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services"

        [[transform.osquery]]
        label = "Osquery - Retrieve Services Running on User Accounts"
        query = "SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE NOT (user_account LIKE '%LocalSystem' OR user_account LIKE '%LocalService' OR user_account LIKE '%NetworkService' OR user_account == null)"

        [[transform.osquery]]
        label = "Retrieve Service Unisgned Executables with Virustotal Link"
        query = "SELECT concat('https://www.virustotal.com/gui/file/', sha1) AS VtLink, name, description, start_type, status, pid, services.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path = authenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != 'trusted'"
        """.strip())  # noqa: E501

        sample_note = dedent("""
                ## Triage and analysis

                ###  Investigating Unusual Process For a Windows Host

                Searching for abnormal Windows processes is a good methodology to find potentially malicious activity within a network. Understanding what is commonly run within an environment and developing baselines for legitimate activity can help uncover potential malware and suspicious behaviors.

                > **Note**:
                > This investigation guide uses the [Osquery Markdown Plugin](https://www.elastic.co/guide/en/security/master/invest-guide-run-osquery.html) introduced in Elastic Stack version 8.5.0. Older Elastic Stack versions will display unrendered Markdown in this guide.

                #### Possible investigation steps

                - Examine the host for derived artifacts that indicates suspicious activities:
                  - Analyze the process executable using a private sandboxed analysis system.
                  - Observe and collect information about the following activities in both the sandbox and the alert subject host:
                    - Attempts to contact external domains and addresses.
                      - Use the Elastic Defend network events to determine domains and addresses contacted by the subject process by filtering by the process' `process.entity_id`.
                      - Examine the DNS cache for suspicious or anomalous entries.
                        - $osquery_0
                    - Use the Elastic Defend registry events to examine registry keys accessed, modified, or created by the related processes in the process tree.
                    - Examine the host services for suspicious or anomalous entries.
                      - $osquery_1
                      - $osquery_2
                      - $osquery_3
                  - Retrieve the files' SHA-256 hash values using the PowerShell `Get-FileHash` cmdlet and search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
                """.strip())  # noqa: E501

        transform = pytoml.loads(osquery_toml)
        rule_dict['rule']['note'] = sample_note
        rule_dict.update(**transform)

        new_rule_contents = TOMLRuleContents.from_dict(rule_dict)
        new_rule = TOMLRule(path=sample_rule.path, contents=new_rule_contents)
        rendered_note = new_rule.contents.to_api_format()['note']

        for pattern in self.osquery_patterns:
            self.assertIn(pattern, rendered_note)

    def test_plugin_conversion(self):
        """Test the conversion function to ensure parsing is correct."""
        sample_rule = self.load_rule()
        rule_dict = sample_rule.contents.to_dict()
        rule_dict['rule']['note'] = "$osquery_0"

        for pattern in self.osquery_patterns:
            transform = guide_plugin_convert_(contents=pattern)
            rule_dict_copy = copy.deepcopy(rule_dict)
            rule_dict_copy.update(**transform)
            new_rule_contents = TOMLRuleContents.from_dict(rule_dict_copy)
            new_rule = TOMLRule(path=sample_rule.path, contents=new_rule_contents)
            rendered_note = new_rule.contents.to_api_format()['note']

            self.assertIn(pattern, rendered_note)
