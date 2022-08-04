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

import yaml
from marshmallow import EXCLUDE, Schema, fields, post_load

from .ghwrap import GithubClient
from .semver import Version
from .utils import INTEGRATION_RULE_DIR, cached, get_etc_path, read_gzip

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
    owner = fields.Dict(required=True)

    @post_load
    def transform_policy_template(self, data, **kwargs):
        data["policy_templates"] = [policy["name"] for policy in data["policy_templates"]]
        return data


def build_integrations_manifest(token: str, overwrite: bool) -> None:
    """Builds a new local copy of manifest.yaml from integrations Github."""
    if overwrite:
        if os.path.exists(MANIFEST_FILE_PATH):
            os.remove(MANIFEST_FILE_PATH)
    rule_integrations = [d.name for d in Path(INTEGRATION_RULE_DIR).glob('*')]
    if "endpoint" in rule_integrations:
        rule_integrations.remove("endpoint")

    final_integration_manifests = {integration: {} for integration in rule_integrations}

    # initialize github client and point to package-storage prod
    github = GithubClient(token)
    client = github.authenticated_client
    organization = client.get_organization("elastic")
    repository = organization.get_repo("package-storage")
    pkg_storage_prod_branch = repository.get_branch("production")
    pkg_storage_branch_sha = pkg_storage_prod_branch.commit.sha

    for integration in rule_integrations:
        integration_manifests = get_integration_manifests(repository, pkg_storage_branch_sha,
                                                          pkg_path=f"packages/{integration}")
        for manifest in integration_manifests:
            validated_manifest = IntegrationManifestSchema(unknown=EXCLUDE).load(manifest)
            package_version = validated_manifest.pop("version")
            final_integration_manifests[integration][package_version] = validated_manifest

    manifest_file = gzip.open(MANIFEST_FILE_PATH, "w+")
    manifest_file_bytes = json.dumps(final_integration_manifests).encode("utf-8")
    manifest_file.write(manifest_file_bytes)


def find_least_compatible_version(package: str, integration: str,
                                  current_stack_version: str, packages_manifest: dict) -> str:
    """Finds least compatible version for specified integration based on stack version supplied."""
    integration_manifests = {k: v for k, v in sorted(packages_manifest[package].items(), key=Version)}

    def compare_versions(int_ver: str, pkg_ver: str) -> bool:
        """Compares integration and package version"""
        pkg_major, pkg_minor = Version(pkg_ver)
        integration_major, integration_minor = Version(int_ver)[:2]

        if int(integration_major) < int(pkg_major) or int(pkg_major) > int(integration_major):
            return False

        compatible = Version(int_ver) <= Version(pkg_ver)
        return compatible

    for version, manifest in integration_manifests.items():
        for kibana_compat_vers in re.sub(r"\>|\<|\=|\^", "", manifest["conditions"]["kibana.version"]).split(" || "):
            if compare_versions(kibana_compat_vers, current_stack_version):
                return version
    raise Exception(f"no compatible version for integration {package}:{integration}")


def get_integration_manifests(repository, sha: str, pkg_path: str) -> list:
    """Iterates over specified integrations from package-storage and combines manifests per version."""
    integration = pkg_path.split("/")[-1]
    versioned_packages = repository.get_dir_contents(pkg_path, ref=sha)
    versions = [p.path.split("/")[-1] for p in versioned_packages]

    manifests = []
    for version in versions:
        contents = repository.get_dir_contents(f"{pkg_path}/{version}", ref=sha)
        print(f"Processing {integration} - Version: {version}")

        processing_version = contents[0].path.split("/")[2]
        manifest_content = [c for c in contents if "manifest" in c.path]

        if len(manifest_content) < 1:
            raise Exception(f"manifest file does not exist for {integration}:{processing_version}")

        path = manifest_content[0].path
        manifest_content = yaml.safe_load(repository.get_contents(path, ref=sha).decoded_content.decode())
        manifests.append(manifest_content)

    return manifests
