# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Test fields in TOML [transform]."""

import copy
import unittest
from textwrap import dedent

import pytoml

from detection_rules.devtools import guide_plugin_convert_
from detection_rules.rule import TOMLRule, TOMLRuleContents
from detection_rules.rule_loader import RuleCollection


class TestGuideMarkdownPlugins(unittest.TestCase):
    """Test the Markdown plugin features within the investigation guide."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.osquery_patterns = [
            """!{osquery{"label":"Osquery - Retrieve DNS Cache","query":"SELECT * FROM dns_cache"}}""",
            """!{osquery{"label":"Osquery - Retrieve All Services","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services"}}""",
            """!{osquery{"label":"Osquery - Retrieve Services Running on User Accounts","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE NOT (user_account LIKE '%LocalSystem' OR user_account LIKE '%LocalService' OR user_account LIKE '%NetworkService' OR user_account == null)"}}""",
            """!{osquery{"label":"Retrieve Service Unisgned Executables with Virustotal Link","query":"SELECT concat('https://www.virustotal.com/gui/file/', sha1) AS VtLink, name, description, start_type, status, pid, services.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path = authenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != 'trusted'"}}""",
        ]

    @staticmethod
    def load_rule() -> TOMLRule:
        rc = RuleCollection()
        windows_rule = {
            "metadata": {
                "creation_date": "2020/08/14",
                "updated_date": "2024/03/28",
                "integration": ["endpoint"],
                "maturity": "production",
                "min_stack_version": "8.3.0",
                "min_stack_comments": "New fields added: required_fields, related_integrations, setup",
            },
            "rule": {
                "author": ["Elastic"],
                "description": "This is a test.",
                "license": "Elastic License v2",
                "from": "now-9m",
                "name": "Test Suspicious Print Spooler SPL File Created",
                "note": "Test note",
                "references": ["https://safebreach.com/Post/How-we-bypassed-CVE-2020-1048-Patch-and-got-CVE-2020-1337"],
                "risk_score": 47,
                "rule_id": "43716252-4a45-4694-aff0-5245b7b6c7cd",
                "setup": "Test setup",
                "severity": "medium",
                "tags": [
                    "Domain: Endpoint",
                    "OS: Windows",
                    "Use Case: Threat Detection",
                    "Tactic: Privilege Escalation",
                    "Resources: Investigation Guide",
                    "Data Source: Elastic Endgame",
                    "Use Case: Vulnerability",
                    "Data Source: Elastic Defend",
                ],
                "timestamp_override": "event.ingested",
                "type": "eql",
                "threat": [
                    {
                        "framework": "MITRE ATT&CK",
                        "tactic": {
                            "id": "TA0004",
                            "name": "Privilege Escalation",
                            "reference": "https://attack.mitre.org/tactics/TA0004/",
                        },
                        "technique": [
                            {
                                "id": "T1068",
                                "name": "Exploitation for Privilege Escalation",
                                "reference": "https://attack.mitre.org/techniques/T1068/",
                            }
                        ],
                    }
                ],
                "index": ["logs-endpoint.events.file-*", "endgame-*"],
                "query": 'file where host.os.type == "windows" and event.type != "deletion"',
                "language": "eql",
            },
        }
        return rc.load_dict(windows_rule)

    def test_transform_guide_markdown_plugins(self) -> None:
        sample_rule = self.load_rule()
        rule_dict = sample_rule.contents.to_dict()
        osquery_toml = dedent(
            """
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
        """.strip()
        )

        sample_note = dedent(
            """
                ## Triage and analysis

                ###  Investigating Unusual Process For a Windows Host

                Searching for abnormal Windows processes is a good methodology to find potentially malicious activity within a network. Understanding what is commonly run within an environment and developing baselines for legitimate activity can help uncover potential malware and suspicious behaviors.

                > **Note**:
                > This investigation guide uses the [Osquery Markdown Plugin](https://www.elastic.co/guide/en/security/current/invest-guide-run-osquery.html) introduced in Elastic Stack version 8.5.0. Older Elastic Stack versions will display unrendered Markdown in this guide.

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
                """.strip()
        )

        transform = pytoml.loads(osquery_toml)
        rule_dict["rule"]["note"] = sample_note
        rule_dict.update(**transform)

        new_rule_contents = TOMLRuleContents.from_dict(rule_dict)
        new_rule = TOMLRule(path=sample_rule.path, contents=new_rule_contents)
        rendered_note = new_rule.contents.to_api_format()["note"]

        for pattern in self.osquery_patterns:
            self.assertIn(pattern, rendered_note)

    def test_plugin_conversion(self):
        """Test the conversion function to ensure parsing is correct."""
        sample_rule = self.load_rule()
        rule_dict = sample_rule.contents.to_dict()
        rule_dict["rule"]["note"] = "$osquery_0"

        for pattern in self.osquery_patterns:
            transform = guide_plugin_convert_(contents=pattern)
            rule_dict_copy = copy.deepcopy(rule_dict)
            rule_dict_copy.update(**transform)
            new_rule_contents = TOMLRuleContents.from_dict(rule_dict_copy)
            new_rule = TOMLRule(path=sample_rule.path, contents=new_rule_contents)
            rendered_note = new_rule.contents.to_api_format()["note"]

            self.assertIn(pattern, rendered_note)
