# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Integration functions."""
from yaml import safe_load

from .utils import load_etc_dump
from .misc import load_current_package_version

class IntegrationPackages():

    def __init__(self):
        packages_manifest = load_etc_dump('integration-manifests.yaml')
        current_stack_version = load_current_package_version()

    def build_integrations_manifest(self):
        """Builds a new local copy of manifest.yaml from integrations Github"""
        ...

    def find_least_compatible_version(self, package: str, integration: str) -> str:
        """Finds least compatible version for specified integration based on stack version supplied"""
        
        return(least_compatible_version)