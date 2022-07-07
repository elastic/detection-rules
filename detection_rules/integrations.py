# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Integration functions."""
import os, json, gzip

from .utils import load_gzip_dump, ETC_DIR, INTEGRATIONS_DIR
from .misc import load_current_package_version
from .ghwrap import get_integration_packages

class IntegrationPackages():

    def __init__(self):
        packages_manifest = load_gzip_dump(ETC_DIR + '/integration-manifests.json.gz')
        current_stack_version = load_current_package_version()

    @staticmethod
    def build_integrations_manifest(token: str) -> None:
        """Builds a new local copy of manifest.yaml from integrations Github"""
        manifest_file_path = ETC_DIR + '/integration-manifests.json.gz'
        if os.path.exists(manifest_file_path): os.remove(manifest_file_path)
        manifest_file = gzip.open(manifest_file_path, "w+")
        
        rule_integrations = os.listdir(INTEGRATIONS_DIR)
        rule_integrations.remove("endpoint")

        final_integration_manifests = dict()
        for ints in rule_integrations:
            integration_manifest = get_integration_packages(token=token,org="elastic",repo="package-storage",
                branch="production",folder=f"packages/{ints}")
            final_integration_manifests.setdefault(ints, integration_manifest[ints])
        manifest_file_bytes = json.dumps(final_integration_manifests).encode("utf-8")
        manifest_file.write(manifest_file_bytes)
        
    def find_least_compatible_version(self, package: str, integration: str) -> str:
        """Finds least compatible version for specified integration based on stack version supplied"""
        
        return(least_compatible_version)