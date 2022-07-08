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

from github import Github

from .semver import Version
from .utils import INTEGRATION_RULE_DIR, get_etc_path


class IntegrationPackages():

    def __init__(self):
        ...

    @staticmethod
    def build_integrations_manifest(token: str, overwrite: bool) -> None:
        """Builds a new local copy of manifest.yaml from integrations Github"""

        if overwrite:
            manifest_file_path = get_etc_path('integration-manifests.json.gz')
            if os.path.exists(manifest_file_path):
                os.remove(manifest_file_path)
        rule_integrations = os.listdir(INTEGRATION_RULE_DIR)
        if "endpoint" in rule_integrations:
            rule_integrations.remove("endpoint")

        final_integration_manifests = dict()
        for ints in rule_integrations:
            integration_manifest = get_integration_packages(token=token, org="elastic", repo="package-storage",
                                                            branch="production", folder=f"packages/{ints}")
            final_integration_manifests.setdefault(ints, integration_manifest[ints])

        manifest_file = gzip.open(manifest_file_path, "w+")
        manifest_file_bytes = json.dumps(final_integration_manifests).encode("utf-8")
        manifest_file.write(manifest_file_bytes)

    @classmethod
    def find_least_compatible_version(cls, package: str, integration: str,
                                      current_stack_version: str, packages_manifest: dict) -> str:
        """Finds least compatible version for specified integration based on stack version supplied"""
        integration_manifests = packages_manifest[package]
        least_compatible_version = None
        compatible_versions = dict()

        def compare_versions(int_ver: str, pkg_ver: str) -> bool:
            """Compares integration and package version"""
            pkg_major, pkg_minor = Version(pkg_ver)
            int_major, int_minor, _ = Version(int_ver)

            if int(int_major) < int(pkg_major) or int(pkg_major) > int(int_major):
                return(False)
            compatible = Version(int_ver) <= Version(pkg_ver)
            return(compatible)

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
        return(least_compatible_version)


def get_integration_packages(token: str, org: str, repo: str, branch: str, folder: str) -> None:
    """Gets integration packages object containing versioned packages and manifest content"""
    ghub = Github(token)
    organization = ghub.get_organization(org)
    repository = organization.get_repo(repo)
    sha = get_sha_for_branch(repository, branch)
    integration_manifest = get_integration_manifests(repository, sha, folder)
    return(integration_manifest)


def get_sha_for_branch(repository, branch: str) -> str:
    """Returns a commit PyGithub object for the specified repository and tag."""
    branches = repository.get_branches()
    matched_branches = [match for match in branches if match.name == branch]
    if matched_branches:
        return(matched_branches[0].commit.sha)
    raise Exception(f"{branch} branch for {repository} repository does not exist")


def get_integration_manifests(repository, sha: str, package_path: str) -> dict:
    """Iterates over specified integrations from package-storage and combines manifests per version"""
    integration = package_path.split("/")[-1]
    versioned_packages = repository.get_dir_contents(package_path, ref=sha)
    versions = [p.path.split("/")[-1] for p in versioned_packages]
    versioned_packages_contents = list()
    for v in versions:
        contents = repository.get_dir_contents(f"{package_path}/{v}", ref=sha)
        versioned_packages_contents.append(contents)

    print(f"Processing {integration} - Versions: {versions}")
    package_version = {f"{integration}": dict()}
    for content in versioned_packages_contents:
        processing_version = content[0].path.split("/")[2]
        manifest_content = [c for c in content if "manifest" in c.path]
        if len(manifest_content) < 1:
            raise Exception(f"manifest file does not exist for {integration}:{processing_version}")
        path = manifest_content[0].path
        manifest_content = yaml.safe_load(repository.get_contents(path, ref=sha).decoded_content.decode())

        # removes large unnecessary fields from manifest data
        [manifest_content.pop(key) for key in ["screenshots", "icons"] if key in manifest_content.keys()]

        package_version[integration][processing_version] = manifest_content

    return(package_version)
