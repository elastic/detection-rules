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
from typing import Generator, List, Tuple, Union, Optional

import requests
from semver import Version
import yaml
from marshmallow import EXCLUDE, Schema, fields, post_load

import kql

from . import ecs
from .beats import flatten_ecs_schema
from .misc import load_current_package_version
from .utils import cached, get_etc_path, read_gzip, unzip
from .schemas import definitions

MANIFEST_FILE_PATH = Path(get_etc_path('integration-manifests.json.gz'))
SCHEMA_FILE_PATH = Path(get_etc_path('integration-schemas.json.gz'))
_notified_integrations = set()


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
    policy_templates = fields.List(fields.Dict)
    owner = fields.Dict(required=False)

    @post_load
    def transform_policy_template(self, data, **kwargs):
        if "policy_templates" in data:
            data["policy_templates"] = [policy["name"] for policy in data["policy_templates"]]
        return data


def build_integrations_manifest(overwrite: bool, rule_integrations: list = [], integration: str = None) -> None:
    """Builds a new local copy of manifest.yaml from integrations Github."""

    def write_manifests(integrations: dict) -> None:
        manifest_file = gzip.open(MANIFEST_FILE_PATH, "w+")
        manifest_file_bytes = json.dumps(integrations).encode("utf-8")
        manifest_file.write(manifest_file_bytes)
        manifest_file.close()

    if overwrite:
        if MANIFEST_FILE_PATH.exists():
            MANIFEST_FILE_PATH.unlink()

    final_integration_manifests = {integration: {} for integration in rule_integrations} \
        or {integration: {}}

    rule_integrations = rule_integrations or [integration]
    for integration in rule_integrations:
        integration_manifests = get_integration_manifests(integration)
        for manifest in integration_manifests:
            validated_manifest = IntegrationManifestSchema(unknown=EXCLUDE).load(manifest)
            package_version = validated_manifest.pop("version")
            final_integration_manifests[integration][package_version] = validated_manifest

    if overwrite and rule_integrations:
        write_manifests(final_integration_manifests)
    elif integration and not overwrite:
        manifest_file = gzip.open(MANIFEST_FILE_PATH, "rb")
        manifest_file_bytes = manifest_file.read()
        manifest_file_contents = json.loads(manifest_file_bytes.decode("utf-8"))
        manifest_file.close()
        manifest_file_contents[integration] = final_integration_manifests[integration]
        write_manifests(manifest_file_contents)

    print(f"final integrations manifests dumped: {MANIFEST_FILE_PATH}")


def build_integrations_schemas(overwrite: bool, integration: str = None) -> None:
    """Builds a new local copy of integration-schemas.json.gz from EPR integrations."""

    saved_integration_schemas = {}

    # Check if the file already exists and handle accordingly
    if overwrite and SCHEMA_FILE_PATH.exists():
        SCHEMA_FILE_PATH.unlink()
        final_integration_schemas = {}
    elif SCHEMA_FILE_PATH.exists():
        final_integration_schemas = load_integrations_schemas()
    else:
        final_integration_schemas = {}

    # Load the integration manifests
    integration_manifests = load_integrations_manifests()

    # if a single integration is specified, only process that integration
    if integration:
        if integration in integration_manifests:
            integration_manifests = {integration: integration_manifests[integration]}
        else:
            raise ValueError(f"Integration {integration} not found in manifest.")

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
                    file_data_bytes = zip_ref.read(file)
                    # Check if the file is a match
                    if glob.fnmatch.fnmatch(file, '*/fields/*.yml'):
                        integration_name = Path(file).parent.parent.name
                        final_integration_schemas[package][version].setdefault(integration_name, {})
                        schema_fields = yaml.safe_load(file_data_bytes)

                        # Parse the schema and add to the integration_manifests
                        data = flatten_ecs_schema(schema_fields)
                        flat_data = {field['name']: field['type'] for field in data}

                        final_integration_schemas[package][version][integration_name].update(flat_data)

                    # add machine learning jobs to the schema
                    if package in list(map(str.lower, definitions.MACHINE_LEARNING_PACKAGES)):
                        if glob.fnmatch.fnmatch(file, '*/ml_module/*ml.json'):
                            ml_module = json.loads(file_data_bytes)
                            job_ids = [job['id'] for job in ml_module['attributes']['jobs']]
                            final_integration_schemas[package][version]['jobs'] = job_ids

                    del file_data_bytes

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
        ESQLRuleData, QueryRuleData, RuleMeta)

    data: QueryRuleData = data
    meta: RuleMeta = meta

    packages_manifest = load_integrations_manifests()
    integrations_schemas = load_integrations_schemas()

    # validate the query against related integration fields
    if (isinstance(data, QueryRuleData) or isinstance(data, ESQLRuleData)) \
       and data.language != 'lucene' and meta.maturity == "production":

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

                # Extract the integration schema fields
                integration_schema, package_version = get_integration_schema_fields(integrations_schemas, package,
                                                                                    integration, min_stack,
                                                                                    packages_manifest, ecs_schema,
                                                                                    data)

                data = {"schema": integration_schema, "package": package, "integration": integration,
                        "stack_version": stack_version, "ecs_version": ecs_version,
                        "package_version": package_version, "endgame_version": endgame_version}
                yield data


def get_integration_schema_fields(integrations_schemas: dict, package: str, integration: str,
                                  min_stack: Version, packages_manifest: dict,
                                  ecs_schema: dict, data: dict) -> dict:
    """Extracts the integration fields to schema based on package integrations."""
    package_version, notice = find_latest_compatible_version(package, integration, min_stack, packages_manifest)
    notify_user_if_update_available(data, notice, integration)

    schema = collect_schema_fields(integrations_schemas, package, package_version, integration)
    schema.update(ecs_schema)

    integration_schema = {key: kql.parser.elasticsearch_type_family(value) for key, value in schema.items()}
    return integration_schema, package_version


def notify_user_if_update_available(data: dict, notice: list, integration: str) -> None:
    """Notifies the user if an update is available, only once per integration."""

    global _notified_integrations
    if notice and data.get("notify", False) and integration not in _notified_integrations:

        # flag to only warn once per integration for available upgrades
        _notified_integrations.add(integration)

        print(f"\n{data.get('name')}")
        print('\n'.join(notice))


def collect_schema_fields(integrations_schemas: dict, package: str, package_version: str,
                          integration: Optional[str] = None) -> dict:
    """Collects the schema fields for a given integration."""
    if integration is None:
        return {field: value for dataset in integrations_schemas[package][package_version] if dataset != "jobs"
                for field, value in integrations_schemas[package][package_version][dataset].items()}

    if integration not in integrations_schemas[package][package_version]:
        raise ValueError(f"Integration {integration} not found in package {package} version {package_version}")

    return integrations_schemas[package][package_version][integration]


def parse_datasets(datasets: list, package_manifest: dict) -> List[Optional[dict]]:
    """Parses datasets into packaged integrations from rule data."""
    packaged_integrations = []
    for value in sorted(datasets):

        # cleanup extra quotes pulled from ast field
        value = value.strip('"')

        integration = 'Unknown'
        if '.' in value:
            package, integration = value.split('.', 1)
        else:
            package = value

        if package in list(package_manifest):
            packaged_integrations.append({"package": package, "integration": integration})
    return packaged_integrations


class SecurityDetectionEngine:
    """Dedicated to Security Detection Engine integration."""

    def __init__(self):
        self.epr_url = "https://epr.elastic.co/package/security_detection_engine/"

    def load_integration_assets(self, package_version: Version) -> dict:
        """Loads integration assets into memory."""

        epr_package_url = f"{self.epr_url}{str(package_version)}/"
        epr_response = requests.get(epr_package_url, timeout=10)
        epr_response.raise_for_status()
        package_obj = epr_response.json()
        zip_url = f"https://epr.elastic.co{package_obj['download']}"
        zip_response = requests.get(zip_url)
        with unzip(zip_response.content) as zip_package:
            asset_file_names = [asset for asset in zip_package.namelist() if "json" in asset]
            assets = {x.split("/")[-1].replace(".json", ""): json.loads(zip_package.read(x).decode('utf-8'))
                      for x in asset_file_names}
        return assets

    def transform_legacy_assets(self, assets: dict) -> dict:
        """Transforms legacy rule assets to historical rules."""
        # this code can be removed after the 8.8 minor release
        # epr prebuilt rule packages should have appropriate file names

        assets_transformed = {}
        for asset_id, contents in assets.items():
            new_asset_id = f"{contents['attributes']['rule_id']}_{contents['attributes']['version']}"
            contents["id"] = new_asset_id
            assets_transformed[new_asset_id] = contents
        return assets_transformed
