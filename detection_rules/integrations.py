# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions to support and interact with Kibana integrations."""
import glob
import gzip
import json
import re
from collections import OrderedDict
from pathlib import Path
from typing import Generator, Tuple, Union, Optional

import requests
from semver import Version
import yaml
from marshmallow import EXCLUDE, Schema, fields, post_load

import kql

from . import ecs
from .beats import flatten_ecs_schema
from .misc import load_current_package_version
from .utils import cached, get_etc_path, read_gzip, unzip

MANIFEST_FILE_PATH = Path(get_etc_path('integration-manifests.json.gz'))
SCHEMA_FILE_PATH = Path(get_etc_path('integration-schemas.json.gz'))


@cached
def load_integrations_manifests() -> dict:
    """Load the consolidated integrations manifest."""
    return json.loads(read_gzip(get_etc_path('integration-manifests.json.gz')))


@cached
def load_integrations_schemas() -> dict:
    """Load the consolidated integrations schemas."""
    return json.loads(read_gzip(get_etc_path('integration-schemas.json.gz')))


class IntegrationManifestSchema(Schema):
    name = fields.Str(required=True)
    version = fields.Str(required=True)
    release = fields.Str(required=True)
    description = fields.Str(required=True)
    download = fields.Str(required=True)
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
        if MANIFEST_FILE_PATH.exists():
            MANIFEST_FILE_PATH.unlink()

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


def build_integrations_schemas(overwrite: bool) -> None:
    """Builds a new local copy of integration-schemas.json.gz from EPR integrations."""

    final_integration_schemas = {}
    saved_integration_schemas = {}

    # Check if the file already exists and handle accordingly
    if overwrite and SCHEMA_FILE_PATH.exists():
        SCHEMA_FILE_PATH.unlink()
    elif SCHEMA_FILE_PATH.exists():
        saved_integration_schemas = load_integrations_schemas()

    # Load the integration manifests
    integration_manifests = load_integrations_manifests()

    # Loop through the packages and versions
    for package, versions in integration_manifests.items():
        print(f"processing {package}")
        final_integration_schemas.setdefault(package, {})
        for version, manifest in versions.items():
            if package in saved_integration_schemas and version in saved_integration_schemas[package]:
                continue

            # Download the zip file
            download_url = f"https://epr.elastic.co{manifest['download']}"
            response = requests.get(download_url)
            response.raise_for_status()

            # Update the final integration schemas
            final_integration_schemas[package].update({version: {}})

            # Open the zip file
            with unzip(response.content) as zip_ref:
                for file in zip_ref.namelist():
                    # Check if the file is a match
                    if glob.fnmatch.fnmatch(file, '*/fields/*.yml'):
                        integration_name = Path(file).parent.parent.name
                        final_integration_schemas[package][version].setdefault(integration_name, {})
                        file_data = zip_ref.read(file)
                        schema_fields = yaml.safe_load(file_data)

                        # Parse the schema and add to the integration_manifests
                        data = flatten_ecs_schema(schema_fields)
                        flat_data = {field['name']: field['type'] for field in data}

                        final_integration_schemas[package][version][integration_name].update(flat_data)

                        del file_data

    # Write the final integration schemas to disk
    with gzip.open(SCHEMA_FILE_PATH, "w") as schema_file:
        schema_file_bytes = json.dumps(final_integration_schemas).encode("utf-8")
        schema_file.write(schema_file_bytes)

    print(f"final integrations manifests dumped: {SCHEMA_FILE_PATH}")


def find_least_compatible_version(package: str, integration: str,
                                  current_stack_version: str, packages_manifest: dict) -> str:
    """Finds least compatible version for specified integration based on stack version supplied."""
    integration_manifests = {k: v for k, v in sorted(packages_manifest[package].items(),
                             key=lambda x: Version.parse(x[0]))}
    current_stack_version = Version.parse(current_stack_version, optional_minor_and_patch=True)

    # filter integration_manifests to only the latest major entries
    major_versions = sorted(list(set([Version.parse(manifest_version).major
                            for manifest_version in integration_manifests])), reverse=True)
    for max_major in major_versions:
        major_integration_manifests = \
            {k: v for k, v in integration_manifests.items() if Version.parse(k).major == max_major}

        # iterates through ascending integration manifests
        # returns latest major version that is least compatible
        for version, manifest in OrderedDict(sorted(major_integration_manifests.items(),
                                                    key=lambda x: Version.parse(x[0]))).items():
            compatible_versions = re.sub(r"\>|\<|\=|\^", "", manifest["conditions"]["kibana"]["version"]).split(" || ")
            for kibana_ver in compatible_versions:
                kibana_ver = Version.parse(kibana_ver)
                # check versions have the same major
                if kibana_ver.major == current_stack_version.major:
                    if kibana_ver <= current_stack_version:
                        return f"^{version}"

    raise ValueError(f"no compatible version for integration {package}:{integration}")


def find_latest_compatible_version(package: str, integration: str,
                                   rule_stack_version: Version,
                                   packages_manifest: dict) -> Union[None, Tuple[str, str]]:
    """Finds least compatible version for specified integration based on stack version supplied."""

    if not package:
        raise ValueError("Package must be specified")

    package_manifest = packages_manifest.get(package)
    if package_manifest is None:
        raise ValueError(f"Package {package} not found in manifest.")

    # Converts the dict keys (version numbers) to Version objects for proper sorting (descending)
    integration_manifests = sorted(package_manifest.items(), key=lambda x: Version.parse(x[0]), reverse=True)
    notice = ""

    for version, manifest in integration_manifests:
        kibana_conditions = manifest.get("conditions", {}).get("kibana", {})
        version_requirement = kibana_conditions.get("version")
        if not version_requirement:
            raise ValueError(f"Manifest for {package}:{integration} version {version} is missing conditions.")

        compatible_versions = re.sub(r"\>|\<|\=|\^", "", version_requirement).split(" || ")

        if not compatible_versions:
            raise ValueError(f"Manifest for {package}:{integration} version {version} is missing compatible versions")

        highest_compatible_version = Version.parse(max(compatible_versions,
                                                       key=lambda x: Version.parse(x)))

        if highest_compatible_version > rule_stack_version:
            # generate notice message that a later integration version is available
            integration = f" {integration.strip()}" if integration else ""

            notice = (f"There is a new integration {package}{integration} version {version} available!",
                      f"Update the rule min_stack version from {rule_stack_version} to "
                      f"{highest_compatible_version} if using new features in this latest version.")

        if highest_compatible_version.major == rule_stack_version.major:
            return version, notice

        else:
            # Check for rules that cross majors
            for compatible_version in compatible_versions:
                if Version.parse(compatible_version) <= rule_stack_version:
                    return version, notice

    raise ValueError(f"no compatible version for integration {package}:{integration}")


def get_integration_manifests(integration: str, prerelease: Optional[bool] = False,
                              kibana_version: Optional[str] = "") -> list:
    """Iterates over specified integrations from package-storage and combines manifests per version."""
    epr_search_url = "https://epr.elastic.co/search"
    if not prerelease:
        prerelease = "false"
    else:
        prerelease = "true"

    # link for search parameters - https://github.com/elastic/package-registry
    epr_search_parameters = {"package": f"{integration}", "prerelease": prerelease,
                             "all": "true", "include_policy_templates": "true"}
    if kibana_version:
        epr_search_parameters["kibana.version"] = kibana_version
    epr_search_response = requests.get(epr_search_url, params=epr_search_parameters, timeout=10)
    epr_search_response.raise_for_status()
    manifests = epr_search_response.json()

    if not manifests:
        raise ValueError(f"EPR search for {integration} integration package returned empty list")

    sorted_manifests = sorted(manifests, key=lambda p: Version.parse(p["version"]), reverse=True)
    print(f"loaded {integration} manifests from the following package versions: "
          f"{[manifest['version'] for manifest in sorted_manifests]}")
    return manifests


def find_latest_integration_version(integration: str, maturity: str, stack_version: Version) -> Version:
    """Finds the latest integration version based on maturity and stack version"""
    prerelease = False if maturity == "ga" else True
    existing_pkgs = get_integration_manifests(integration, prerelease, str(stack_version))
    if maturity == "ga":
        existing_pkgs = [pkg for pkg in existing_pkgs if not
                         Version.parse(pkg["version"]).prerelease]
    if maturity == "beta":
        existing_pkgs = [pkg for pkg in existing_pkgs if
                         Version.parse(pkg["version"]).prerelease]
    return max([Version.parse(pkg["version"]) for pkg in existing_pkgs])


def get_integration_schema_data(data, meta, package_integrations: dict) -> Generator[dict, None, None]:
    """Iterates over specified integrations from package-storage and combines schemas per version."""

    # lazy import to avoid circular import
    from .rule import (  # pylint: disable=import-outside-toplevel
        QueryRuleData, RuleMeta)

    data: QueryRuleData = data
    meta: RuleMeta = meta

    packages_manifest = load_integrations_manifests()
    integrations_schemas = load_integrations_schemas()

    # validate the query against related integration fields
    if isinstance(data, QueryRuleData) and data.language != 'lucene' and meta.maturity == "production":

        # flag to only warn once per integration for available upgrades
        notify_update_available = True

        for stack_version, mapping in meta.get_validation_stack_versions().items():
            ecs_version = mapping['ecs']
            endgame_version = mapping['endgame']

            ecs_schema = ecs.flatten_multi_fields(ecs.get_schema(ecs_version, name='ecs_flat'))

            for pk_int in package_integrations:
                package = pk_int["package"]
                integration = pk_int["integration"]

                # Use the minimum stack version from the package not the rule
                min_stack = meta.min_stack_version or load_current_package_version()
                min_stack = Version.parse(min_stack, optional_minor_and_patch=True)

                package_version, notice = find_latest_compatible_version(package=package,
                                                                         integration=integration,
                                                                         rule_stack_version=min_stack,
                                                                         packages_manifest=packages_manifest)

                if notify_update_available and notice and data.get("notify", False):
                    # Notify for now, as to not lock rule stacks to integrations
                    notify_update_available = False
                    print(f"\n{data.get('name')}")
                    print(*notice)

                schema = {}
                if integration is None:
                    # Use all fields from each dataset
                    for dataset in integrations_schemas[package][package_version]:
                        schema.update(integrations_schemas[package][package_version][dataset])
                else:
                    if integration not in integrations_schemas[package][package_version]:
                        raise ValueError(f"Integration {integration} not found in package {package} "
                                         f"version {package_version}")
                    schema = integrations_schemas[package][package_version][integration]
                schema.update(ecs_schema)
                integration_schema = {k: kql.parser.elasticsearch_type_family(v) for k, v in schema.items()}

                data = {"schema": integration_schema, "package": package, "integration": integration,
                        "stack_version": stack_version, "ecs_version": ecs_version,
                        "package_version": package_version, "endgame_version": endgame_version}
                yield data
