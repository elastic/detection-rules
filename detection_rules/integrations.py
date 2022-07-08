# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Integration functions."""
import os
import json
import gzip
import re

from .utils import load_gzip_dump, ETC_DIR, INTEGRATIONS_DIR
from .misc import load_current_package_version
from .ghwrap import get_integration_packages
from packaging import version
from distutils.version import StrictVersion

class IntegrationPackages():

    def __init__(self):
        ...

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
        
    @classmethod
    def find_least_compatible_version(self, package: str, integration: str) -> str:
        """Finds least compatible version for specified integration based on stack version supplied"""
        packages_manifest = load_gzip_dump(ETC_DIR + '/integration-manifests.json.gz')
        current_stack_version = load_current_package_version()
        integration_manifests = packages_manifest[package]
        compatible_versions = dict.fromkeys(integration_manifests.keys())
        least_compatible_version = None
        final_compatible_versions = dict()

        def compare_versions(int_ver: str, pkg_ver: str) -> bool:
            """Compares integration and package version"""
            pkg_major, pkg_minor = pkg_ver.split(".")
            int_major, int_minor = int_ver.split(".")[:2]
            
            if int(int_major) < int(pkg_major)or int(pkg_major) > int(int_major): return(False)
            compatible = version.parse(int_ver) <= version.parse(pkg_ver)
            return(compatible)

        for ver, manifest in integration_manifests.items():
            kibana_compat_vers = re.sub("\>|\<|\=|\^", "", manifest["conditions"]["kibana.version"])
            kibana_compat_vers = kibana_compat_vers.split(" || ")
            bool_checks = list()
            for kcv in kibana_compat_vers:
                bool_checks.append(compare_versions(kcv, current_stack_version))
            if any(bool_checks):
                final_compatible_versions.setdefault(ver, True)

        if len(list(final_compatible_versions.keys())) > 0:
            compatible_version_list = list(final_compatible_versions.keys())
            compatible_version_list.sort(key=version.parse)
            least_compatible_version = compatible_version_list[0]
        return(least_compatible_version)