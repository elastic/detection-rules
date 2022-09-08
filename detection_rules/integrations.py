# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions to support and interact with Kibana integrations."""
import gzip
import json
import os
import re
from pathlib import Path
from typing import Union

import requests
import yaml
from marshmallow import EXCLUDE, Schema, fields, post_load

from .ghwrap import GithubClient
from .semver import Version
from .utils import cached, get_etc_path, read_gzip

MANIFEST_FILE_PATH = Path(get_etc_path('integration-manifests.json.gz'))


@cached
def load_integrations_manifests() -> dict:
    """Load the consolidated integrations manifest."""
    return json.loads(read_gzip(get_etc_path('integration-manifests.json.gz')))


class IntegrationManifestSchema(Schema):
    name = fields.Str(required=True)
    version = fields.Str(required=True)
    release = fields.Str(required=True)
    description = fields.Str(required=True)
    conditions = fields.Dict(required=True)
    policy_templates = fields.List(fields.Dict, required=True)
    owner = fields.Dict(required=False)

    @post_load
    def transform_policy_template(self, data, **kwargs):
        data["policy_templates"] = [policy["name"] for policy in data["policy_templates"]]
        return data


def build_integrations_manifest(overwrite: bool, rule_integrations: list) -> None:
    """Builds a new local copy of manifest.yaml from integrations Github."""
    if overwrite:
        if os.path.exists(MANIFEST_FILE_PATH):
            os.remove(MANIFEST_FILE_PATH)

    final_integration_manifests = {integration: {} for integration in rule_integrations}

    for integration in rule_integrations:
        integration_manifests = get_integration_manifests(integration)
        for manifest in integration_manifests:
            validated_manifest = IntegrationManifestSchema(unknown=EXCLUDE).load(manifest)
            package_version = validated_manifest.pop("version")
            final_integration_manifests[integration][package_version] = validated_manifest

    manifest_file = gzip.open(MANIFEST_FILE_PATH, "w+")
    manifest_file_bytes = json.dumps(final_integration_manifests).encode("utf-8")
    manifest_file.write(manifest_file_bytes)
    print(f"final integrations manifests dumped: {MANIFEST_FILE_PATH}")


def find_least_compatible_version(package: str, integration: str,
                                  current_stack_version: str, packages_manifest: dict) -> Union[str, None]:
    """Finds least compatible version for specified integration based on stack version supplied."""
    integration_manifests = {k: v for k, v in sorted(packages_manifest[package].items(), key=Version)}

    # trim integration_manifests to only the latest major entries
    major_versions = \
        list(set([Version(manifest_version)[0] for manifest_version, manifest in integration_manifests.items()]))
    major_versions.sort(reverse=True)
    latest_major_integration_manifests = \
        {k: v for k, v in integration_manifests.items() if major_versions[0] == Version(k)[0]}

    def compare_versions(int_ver: str, pkg_ver: str) -> bool:
        """Compares integration and package version"""
        pkg_major, pkg_minor = Version(pkg_ver)
        integration_major, integration_minor = Version(int_ver)[:2]

        if int(integration_major) < int(pkg_major) or int(pkg_major) > int(integration_major):
            return False

        compatible = Version(int_ver) <= Version(pkg_ver)
        return compatible

    for version, manifest in latest_major_integration_manifests.items():
        for kibana_compat_vers in re.sub(r"\>|\<|\=|\^", "", manifest["conditions"]["kibana.version"]).split(" || "):
            if compare_versions(kibana_compat_vers, current_stack_version):
                return f"^{version}"
    print(f"no compatible version for integration {package}:{integration}")
    return None


def get_integration_manifests(integration: str) -> list:
    """Iterates over specified integrations from package-storage and combines manifests per version."""
    epr_search_url = "https://epr.elastic.co/search"
    epr_search_parameters = {"package":f"{integration}","prerelease":"true",
                        "all":"true","include_policy_templates":"true"}
    epr_search_response = requests.get(epr_search_url, params=epr_search_parameters)
    manifests = json.loads(epr_search_response.content)
    if epr_search_response.status_code != 200 or manifests == []:
        raise Exception(f"EPR search for {integration} integration package failed")
    print(f"loaded {integration} manifests from the following package versions: {[manifest['version'] for manifest in manifests]}")
    return manifests