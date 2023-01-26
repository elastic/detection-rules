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
from typing import Generator, Union

import requests
import yaml
from marshmallow import EXCLUDE, Schema, fields, post_load

import kql

from . import ecs
from .beats import flatten_ecs_schema
from .semver import Version
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
                        schema_fields = yaml.load(file_data, Loader=yaml.FullLoader)

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
                             key=lambda x: Version(str(x[0])))}

    # filter integration_manifests to only the latest major entries
    major_versions = sorted(list(set([Version(manifest_version)[0] for manifest_version in integration_manifests])),
                            reverse=True)
    for max_major in major_versions:
        major_integration_manifests = \
            {k: v for k, v in integration_manifests.items() if Version(k)[0] == max_major}

        # iterates through ascending integration manifests
        # returns latest major version that is least compatible
        for version, manifest in OrderedDict(sorted(major_integration_manifests.items(),
                                                    key=lambda x: Version(str(x[0])))).items():
            compatible_versions = re.sub(r"\>|\<|\=|\^", "", manifest["conditions"]["kibana"]["version"]).split(" || ")
            for kibana_ver in compatible_versions:
                # check versions have the same major
                if int(kibana_ver[0]) == int(current_stack_version[0]):
                    if Version(kibana_ver) <= Version(current_stack_version + ".0"):
                        return f"^{version}"

    raise ValueError(f"no compatible version for integration {package}:{integration}")


def find_latest_compatible_version(package: str, integration: str,
                                   rule_stack_version: str, packages_manifest: dict) -> Union[None, str]:
    """Finds least compatible version for specified integration based on stack version supplied."""

    if not package:
        raise ValueError("Package must be specified")

    package_manifest = packages_manifest.get(package)
    if package_manifest is None:
        raise ValueError(f"Package {package} not found in manifest.")

    # Converts the dict keys (version numbers) to Version objects for proper sorting (descending)
    integration_manifests = sorted(package_manifest.items(), key=lambda x: Version(str(x[0])), reverse=True)

    for version, manifest in integration_manifests:
        kibana_conditions = manifest.get("conditions", {}).get("kibana", {})
        version_requirement = kibana_conditions.get("version")
        if not version_requirement:
            raise ValueError(f"Manifest for {package}:{integration} version {version} is missing conditions.")

        compatible_versions = re.sub(r"\>|\<|\=|\^", "", version_requirement).split(" || ")

        if not compatible_versions:
            raise ValueError(f"Manifest for {package}:{integration} version {version} is missing compatible versions")

        highest_compatible_version = max(compatible_versions, key=lambda x: Version(x))

        if Version(highest_compatible_version) > Version(rule_stack_version):
            # TODO: Determine if we should raise an error here or not
            integration = f" {integration}" if integration else ""
            print(f"Integration {package}{integration} version {version} has a higher stack version requirement.",
                  f"Consider updating min_stack version from {rule_stack_version} to "
                  f"{highest_compatible_version} to support this version.")

        elif int(highest_compatible_version[0]) == int(rule_stack_version[0]):
            return version

    raise ValueError(f"no compatible version for integration {package}:{integration}")


def get_integration_manifests(integration: str) -> list:
    """Iterates over specified integrations from package-storage and combines manifests per version."""
    epr_search_url = "https://epr.elastic.co/search"

    # link for search parameters - https://github.com/elastic/package-registry
    epr_search_parameters = {"package": f"{integration}", "prerelease": "false",
                             "all": "true", "include_policy_templates": "true"}
    epr_search_response = requests.get(epr_search_url, params=epr_search_parameters)
    epr_search_response.raise_for_status()
    manifests = epr_search_response.json()

    if not manifests:
        raise ValueError(f"EPR search for {integration} integration package returned empty list")

    print(f"loaded {integration} manifests from the following package versions: "
          f"{[manifest['version'] for manifest in manifests]}")
    return manifests


def get_integration_schema_data(data, meta, package_integrations: dict) -> Generator[dict, None, None]:
    """Iterates over specified integrations from package-storage and combines schemas per version."""

    # lazy import to avoid circular import
    from .rule import (  # pylint: disable=import-outside-toplevel
        QueryRuleData, RuleMeta
    )

    data: QueryRuleData = data
    meta: RuleMeta = meta

    packages_manifest = load_integrations_manifests()
    integrations_schemas = load_integrations_schemas()

    # validate the query against related integration fields
    if isinstance(data, QueryRuleData) and data.language != 'lucene' and meta.maturity == "production":

        for stack_version, mapping in meta.get_validation_stack_versions().items():
            ecs_version = mapping['ecs']

            ecs_schema = ecs.flatten_multi_fields(ecs.get_schema(ecs_version, name='ecs_flat'))

            for pk_int in package_integrations:
                package = pk_int["package"]
                integration = pk_int["integration"]

                package_version = find_latest_compatible_version(package=package,
                                                                 integration=integration,
                                                                 rule_stack_version=meta.min_stack_version,
                                                                 packages_manifest=packages_manifest)

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
                        "package_version": package_version}
                yield data
