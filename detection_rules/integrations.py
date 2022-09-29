# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions to support and interact with Kibana integrations."""
import gzip
import json
import os
import re
from collections import OrderedDict
from pathlib import Path

import requests
from marshmallow import EXCLUDE, Schema, fields, post_load

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
                                  current_stack_version: str, packages_manifest: dict) -> str:
    """Finds least compatible version for specified integration based on stack version supplied."""
    integration_manifests = {k: v for k, v in sorted(packages_manifest[package].items(),
                             key=lambda x: Version(str(x[0])))}

    # filter integration_manifests to only the latest major entries
    max_major, *_ = max([Version(manifest_version) for manifest_version in integration_manifests])
    latest_major_integration_manifests = \
        {k: v for k, v in integration_manifests.items() if Version(k)[0] == max_major}

    # iterates through ascending integration manifests
    # returns latest major version that is least compatible
    for version, manifest in OrderedDict(sorted(latest_major_integration_manifests.items(),
                                                key=lambda x: Version(str(x[0])))).items():
        compatible_versions = re.sub(r"\>|\<|\=|\^", "", manifest["conditions"]["kibana"]["version"]).split(" || ")
        for kibana_ver in compatible_versions:
            # check versions have the same major
            if int(kibana_ver[0]) == int(current_stack_version[0]):
                if Version(kibana_ver) <= Version(current_stack_version + ".0"):
                    return f"^{version}"

    raise ValueError(f"no compatible version for integration {package}:{integration}")


def get_integration_manifests(integration: str) -> list:
    """Iterates over specified integrations from package-storage and combines manifests per version."""
    epr_search_url = "https://epr.elastic.co/search"

    # link for search parameters - https://github.com/elastic/package-registry
    epr_search_parameters = {"package": f"{integration}", "prerelease": "true",
                             "all": "true", "include_policy_templates": "true"}
    epr_search_response = requests.get(epr_search_url, params=epr_search_parameters)
    epr_search_response.raise_for_status()
    manifests = epr_search_response.json()

    if not manifests:
        raise ValueError(f"EPR search for {integration} integration package returned empty list")

    print(f"loaded {integration} manifests from the following package versions: "
          f"{[manifest['version'] for manifest in manifests]}")
    return manifests
