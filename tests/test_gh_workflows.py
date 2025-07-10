# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Tests for GitHub workflow functionality."""

import unittest

import yaml

from detection_rules.schemas import RULES_CONFIG, get_stack_versions
from detection_rules.utils import ROOT_DIR

GITHUB_FILES = ROOT_DIR / ".github"
GITHUB_WORKFLOWS = GITHUB_FILES / "workflows"


class TestWorkflows(unittest.TestCase):
    """Test GitHub workflow functionality."""

    @unittest.skipIf(RULES_CONFIG.bypass_version_lock, "Version lock bypassed")
    def test_matrix_to_lock_version_defaults(self):
        """Test that the default versions in the lock-versions workflow mirror those from the schema-map."""
        lock_workflow_file = GITHUB_WORKFLOWS / "lock-versions.yml"
        lock_workflow = yaml.safe_load(lock_workflow_file.read_text())
        lock_versions = lock_workflow[True]["workflow_dispatch"]["inputs"]["branches"]["default"].split(",")

        matrix_versions = get_stack_versions(drop_patch=True)
        err_msg = "lock-versions workflow default does not match current matrix in stack-schema-map"
        self.assertListEqual(lock_versions, matrix_versions[:-1], err_msg)
