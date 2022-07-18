# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Integration functions."""
import gzip
import json
import os
import re

import yaml
from marshmallow import EXCLUDE, Schema, fields, post_load

from .ghwrap import GithubClient
from .semver import Version
from .utils import INTEGRATION_RULE_DIR, get_etc_path


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
    manifest_file_path = get_etc_path('integration-manifests.json.gz')
    if overwrite:
        if os.path.exists(manifest_file_path):
            os.remove(manifest_file_path)
    rule_integrations = os.listdir(INTEGRATION_RULE_DIR)
    if "endpoint" in rule_integrations:
        rule_integrations.remove("endpoint")

    final_integration_manifests = {key: dict() for key in rule_integrations}
    for ints in rule_integrations:
        integration_manifests = get_integration_packages(token=token, org="elastic", repo="package-storage",
                                                         branch="production", folder=f"packages/{ints}")
        for int_man in integration_manifests:
            validated_manifest = IntegrationManifestSchema(unknown=EXCLUDE).load(int_man)
            package_version = validated_manifest.pop("version")
            final_integration_manifests[ints][package_version] = validated_manifest

    manifest_file = gzip.open(manifest_file_path, "w+")
    manifest_file_bytes = json.dumps(final_integration_manifests).encode("utf-8")
    manifest_file.write(manifest_file_bytes)


def find_least_compatible_version(package: str, integration: str,
                                  current_stack_version: str, packages_manifest: dict) -> str:
    """Finds least compatible version for specified integration based on stack version supplied."""
    integration_manifests = packages_manifest[package]
    least_compatible_version = None
    compatible_versions = dict()

    def compare_versions(int_ver: str, pkg_ver: str) -> bool:
        """Compares integration and package version"""
        pkg_major, pkg_minor = Version(pkg_ver)
        int_major, int_minor = Version(int_ver)[:2]

        if int(int_major) < int(pkg_major) or int(pkg_major) > int(int_major):
            return(False)
        compatible = Version(int_ver) <= Version(pkg_ver)
        return compatible

    for ver, manifest in integration_manifests.items():
        kibana_compat_vers = re.sub(r"\>|\<|\=|\^", "", manifest["conditions"]["kibana.version"])
        kibana_compat_vers = kibana_compat_vers.split(" || ")
        bool_checks = list()
        for kcv in kibana_compat_vers:
            bool_checks.append(compare_versions(kcv, current_stack_version))
        if any(bool_checks):
            compatible_versions.setdefault(ver, True)

    if len(list(compatible_versions.keys())) > 0:
        compatible_version_list = list(compatible_versions.keys())
        compatible_version_list.sort(key=Version)
        least_compatible_version = compatible_version_list[0]
    else:
        raise Exception(f"no compatible version for integration {package}:{integration}")
    return least_compatible_version


def get_integration_packages(token: str, org: str, repo: str, branch: str, folder: str) -> dict:
    """Gets integration packages object containing versioned packages and manifest content."""
    github = GithubClient(token)
    client = github.authenticated_client
    organization = client.get_organization(org)
    repository = organization.get_repo(repo)
    sha = get_sha_for_branch(repository, branch)
    integration_manifest = get_integration_manifests(repository, sha, folder)
    return integration_manifest


def get_sha_for_branch(repository, branch: str) -> str:
    """Returns a commit PyGithub object for the specified repository and tag."""
    branches = repository.get_branches()
    matched_branches = [match for match in branches if match.name == branch]
    if matched_branches:
        return matched_branches[0].commit.sha
    raise Exception(f"{branch} branch for {repository} repository does not exist")


def get_integration_manifests(repository, sha: str, package_path: str) -> dict:
    """Iterates over specified integrations from package-storage and combines manifests per version."""
    integration = package_path.split("/")[-1]
    versioned_packages = repository.get_dir_contents(package_path, ref=sha)
    versions = [p.path.split("/")[-1] for p in versioned_packages]
    versioned_packages_contents = list()
    for v in versions:
        contents = repository.get_dir_contents(f"{package_path}/{v}", ref=sha)
        versioned_packages_contents.append(contents)

    print(f"Processing {integration} - Versions: {versions}")
    manifests = list()
    for content in versioned_packages_contents:
        processing_version = content[0].path.split("/")[2]
        manifest_content = [c for c in content if "manifest" in c.path]
        if len(manifest_content) < 1:
            raise Exception(f"manifest file does not exist for {integration}:{processing_version}")
        path = manifest_content[0].path
        manifest_content = yaml.safe_load(repository.get_contents(path, ref=sha).decoded_content.decode())
        manifests.append(manifest_content)

    return manifests
