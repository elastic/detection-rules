# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions to support and interact with Kibana integrations."""

import fnmatch
import gzip
import json
import re
from collections import OrderedDict, defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import kql  # type: ignore[reportMissingTypeStubs]
import requests
import yaml
from marshmallow import EXCLUDE, Schema, fields, post_load
from semver import Version

from . import ecs
from .beats import flatten_ecs_schema
from .config import load_current_package_version
from .schemas import definitions
from .utils import cached, get_etc_path, read_gzip, unzip

if TYPE_CHECKING:
    from .rule import QueryRuleData, RuleMeta


MANIFEST_FILE_PATH = get_etc_path(["integration-manifests.json.gz"])
DEFAULT_MAX_RULE_VERSIONS = 1
SCHEMA_FILE_PATH = get_etc_path(["integration-schemas.json.gz"])


_notified_integrations: set[str] = set()


@cached
def load_integrations_manifests() -> dict[str, Any]:
    """Load the consolidated integrations manifest."""
    return json.loads(read_gzip(get_etc_path(["integration-manifests.json.gz"])))


@cached
def load_integrations_schemas() -> dict[str, Any]:
    """Load the consolidated integrations schemas."""
    return json.loads(read_gzip(get_etc_path(["integration-schemas.json.gz"])))


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
    def transform_policy_template(self, data: dict[str, Any], **_: Any) -> dict[str, Any]:
        if "policy_templates" in data:
            data["policy_templates"] = [policy["name"] for policy in data["policy_templates"]]
        return data


def build_integrations_manifest(
    overwrite: bool,
    rule_integrations: list[str] = [],  # noqa: B006
    integration: str | None = None,
    prerelease: bool = False,
) -> None:
    """Builds a new local copy of manifest.yaml from integrations Github."""

    def write_manifests(integrations: dict[str, Any]) -> None:
        manifest_file_bytes = json.dumps(integrations).encode("utf-8")
        with gzip.open(MANIFEST_FILE_PATH, "wb") as f:
            _ = f.write(manifest_file_bytes)

    if overwrite and MANIFEST_FILE_PATH.exists():
        MANIFEST_FILE_PATH.unlink()

    final_integration_manifests: dict[str, dict[str, Any]] = {}
    if rule_integrations:
        final_integration_manifests = {integration: {} for integration in rule_integrations}
    elif integration:
        final_integration_manifests = {integration: {}}
        rule_integrations = [integration]

    for _integration in rule_integrations:
        integration_manifests = get_integration_manifests(_integration, prerelease=prerelease)
        for manifest in integration_manifests:
            validated_manifest = IntegrationManifestSchema(unknown=EXCLUDE).load(manifest)  # type: ignore[reportUnknownVariableType]
            package_version = validated_manifest.pop("version")  # type: ignore[reportOptionalMemberAccess]
            final_integration_manifests[_integration][package_version] = validated_manifest

    if overwrite and rule_integrations:
        write_manifests(final_integration_manifests)
    elif integration and not overwrite:
        with gzip.open(MANIFEST_FILE_PATH, "rb") as manifest_file:
            manifest_file_bytes = manifest_file.read()

        manifest_file_contents = json.loads(manifest_file_bytes.decode("utf-8"))
        manifest_file_contents[integration] = final_integration_manifests[integration]
        write_manifests(manifest_file_contents)

    print(f"final integrations manifests dumped: {MANIFEST_FILE_PATH}")


def build_integrations_schemas(overwrite: bool, integration: str | None = None) -> None:
    """Builds a new local copy of integration-schemas.json.gz from EPR integrations."""

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
        final_integration_schemas.setdefault(package, {})  # type: ignore[reportUnknownMemberType]
        for version, manifest in versions.items():
            if package in final_integration_schemas and version in final_integration_schemas[package]:
                continue

            # Download the zip file
            download_url = f"https://epr.elastic.co{manifest['download']}"
            response = requests.get(download_url, timeout=30)
            response.raise_for_status()

            # Update the final integration schemas
            final_integration_schemas[package].update({version: {}})  # type: ignore[reportUnknownMemberType]

            # Open the zip file
            with unzip(response.content) as zip_ref:
                for file in zip_ref.namelist():
                    file_data_bytes = zip_ref.read(file)
                    # Check if the file is a match
                    if fnmatch.fnmatch(file, "*/fields/*.yml"):
                        integration_name = Path(file).parent.parent.name
                        final_integration_schemas[package][version].setdefault(integration_name, {})  # type: ignore[reportUnknownMemberType]
                        schema_fields = yaml.safe_load(file_data_bytes)

                        # Parse the schema and add to the integration_manifests
                        data = flatten_ecs_schema(schema_fields)
                        flat_data = {field["name"]: field["type"] for field in data}

                        final_integration_schemas[package][version][integration_name].update(flat_data)  # type: ignore[reportUnknownMemberType]

                    # add machine learning jobs to the schema
                    if package in [str.lower(x) for x in definitions.MACHINE_LEARNING_PACKAGES] and fnmatch.fnmatch(
                        file, "*/ml_module/*ml.json"
                    ):
                        ml_module = json.loads(file_data_bytes)
                        job_ids = [job["id"] for job in ml_module["attributes"]["jobs"]]
                        final_integration_schemas[package][version]["jobs"] = job_ids

                    del file_data_bytes

    # Write the final integration schemas to disk
    with gzip.open(SCHEMA_FILE_PATH, "w") as schema_file:
        schema_file_bytes = json.dumps(final_integration_schemas).encode("utf-8")
        _ = schema_file.write(schema_file_bytes)

    print(f"final integrations manifests dumped: {SCHEMA_FILE_PATH}")


def find_least_compatible_version(
    package: str,
    integration: str,
    current_stack_version: str,
    packages_manifest: dict[str, Any],
) -> str:
    """Finds least compatible version for specified integration based on stack version supplied."""
    integration_manifests = dict(sorted(packages_manifest[package].items(), key=lambda x: Version.parse(x[0])))
    stack_version = Version.parse(current_stack_version, optional_minor_and_patch=True)

    # filter integration_manifests to only the latest major entries
    major_versions = sorted(
        {Version.parse(manifest_version).major for manifest_version in integration_manifests},
        reverse=True,
    )
    for max_major in major_versions:
        major_integration_manifests = {
            k: v for k, v in integration_manifests.items() if Version.parse(k).major == max_major
        }

        # iterates through ascending integration manifests
        # returns latest major version that is least compatible
        for version, manifest in OrderedDict(
            sorted(major_integration_manifests.items(), key=lambda x: Version.parse(x[0]))
        ).items():
            compatible_versions = re.sub(r"\>|\<|\=|\^|\~", "", manifest["conditions"]["kibana"]["version"]).split(
                " || "
            )
            for kibana_ver in compatible_versions:
                _kibana_ver = Version.parse(kibana_ver)
                # check versions have the same major
                if _kibana_ver.major == stack_version.major and _kibana_ver <= stack_version:
                    return f"^{version}"

    raise ValueError(f"no compatible version for integration {package}:{integration}")


def find_latest_compatible_version(
    package: str,
    integration: str,
    rule_stack_version: Version,
    packages_manifest: dict[str, Any],
) -> tuple[str, list[str]]:
    """Finds latest compatible version for specified integration based on stack version supplied."""

    if not package:
        raise ValueError("Package must be specified")

    package_manifest = packages_manifest.get(package)
    if package_manifest is None:
        raise ValueError(f"Package {package} not found in manifest.")

    # Converts the dict keys (version numbers) to Version objects for proper sorting (descending)
    integration_manifests = sorted(package_manifest.items(), key=lambda x: Version.parse(x[0]), reverse=True)
    notice = [""]

    for version, manifest in integration_manifests:
        kibana_conditions = manifest.get("conditions", {}).get("kibana", {})
        version_requirement = kibana_conditions.get("version")
        if not version_requirement:
            raise ValueError(f"Manifest for {package}:{integration} version {version} is missing conditions.")

        compatible_versions = re.sub(r"\>|\<|\=|\^|\~", "", version_requirement).split(" || ")

        if not compatible_versions:
            raise ValueError(f"Manifest for {package}:{integration} version {version} is missing compatible versions")

        highest_compatible_version = Version.parse(max(compatible_versions, key=lambda x: Version.parse(x)))

        if highest_compatible_version > rule_stack_version:
            # generate notice message that a later integration version is available
            integration = f" {integration.strip()}" if integration else ""

            notice = [
                f"There is a new integration {package}{integration} version {version} available!",
                f"Update the rule min_stack version from {rule_stack_version} to "
                f"{highest_compatible_version} if using new features in this latest version.",
            ]

        if highest_compatible_version.major == rule_stack_version.major:
            return version, notice

        # Check for rules that cross majors
        for compatible_version in compatible_versions:
            if Version.parse(compatible_version) <= rule_stack_version:
                return version, notice

    raise ValueError(f"no compatible version for integration {package}:{integration}")


def get_integration_manifests(
    integration: str,
    prerelease: bool | None = False,
    kibana_version: str | None = "",
) -> list[Any]:
    """Iterates over specified integrations from package-storage and combines manifests per version."""
    epr_search_url = "https://epr.elastic.co/search"
    prerelease_str = "true" if prerelease else "false"

    # link for search parameters - https://github.com/elastic/package-registry
    epr_search_parameters = {
        "package": f"{integration}",
        "prerelease": prerelease_str,
        "all": "true",
        "include_policy_templates": "true",
    }
    if kibana_version:
        epr_search_parameters["kibana.version"] = kibana_version
    epr_search_response = requests.get(epr_search_url, params=epr_search_parameters, timeout=10)
    epr_search_response.raise_for_status()
    manifests = epr_search_response.json()

    if not manifests:
        raise ValueError(f"EPR search for {integration} integration package returned empty list")

    sorted_manifests = sorted(manifests, key=lambda p: Version.parse(p["version"]), reverse=True)
    print(
        f"loaded {integration} manifests from the following package versions: "
        f"{[manifest['version'] for manifest in sorted_manifests]}"
    )
    return manifests


def find_latest_integration_version(integration: str, maturity: str, stack_version: Version) -> Version:
    """Finds the latest integration version based on maturity and stack version"""
    prerelease = maturity != "ga"
    existing_pkgs = get_integration_manifests(integration, prerelease, str(stack_version))
    if maturity == "ga":
        existing_pkgs = [pkg for pkg in existing_pkgs if not Version.parse(pkg["version"]).prerelease]
    if maturity == "beta":
        existing_pkgs = [pkg for pkg in existing_pkgs if Version.parse(pkg["version"]).prerelease]
    return max([Version.parse(pkg["version"]) for pkg in existing_pkgs])


# Using `Any` here because `integrations` and `rule` modules are tightly coupled
def get_integration_schema_data(
    data: Any,  # type: ignore[reportRedeclaration]
    meta: Any,  # type: ignore[reportRedeclaration]
    package_integrations: list[dict[str, Any]],
) -> Iterator[dict[str, Any]]:
    """Iterates over specified integrations from package-storage and combines schemas per version."""

    data: QueryRuleData = data  # type: ignore[reportAssignmentType]  # noqa: PLW0127
    meta: RuleMeta = meta  # noqa: PLW0127

    packages_manifest = load_integrations_manifests()
    integrations_schemas = load_integrations_schemas()

    # validate the query against related integration fields
    if data.language != "lucene" and meta.maturity == "production":
        for stack_version, mapping in meta.get_validation_stack_versions().items():
            ecs_version = mapping["ecs"]
            endgame_version = mapping["endgame"]

            ecs_schema = ecs.flatten_multi_fields(ecs.get_schema(ecs_version, name="ecs_flat"))

            for pk_int in package_integrations:
                package = pk_int["package"]
                integration = pk_int["integration"]

                # Use the minimum stack version from the package not the rule
                min_stack = meta.min_stack_version or load_current_package_version()
                min_stack = Version.parse(min_stack, optional_minor_and_patch=True)

                # Extract the integration schema fields
                integration_schema, package_version = get_integration_schema_fields(
                    integrations_schemas,
                    package,
                    integration,
                    min_stack,
                    packages_manifest,
                    ecs_schema,
                    data,
                )

                yield {
                    "schema": integration_schema,
                    "package": package,
                    "integration": integration,
                    "stack_version": stack_version,
                    "ecs_version": ecs_version,
                    "package_version": package_version,
                    "endgame_version": endgame_version,
                }


def get_integration_schema_fields(  # noqa: PLR0913
    integrations_schemas: dict[str, Any],
    package: str,
    integration: str,
    min_stack: Version,
    packages_manifest: dict[str, Any],
    ecs_schema: dict[str, Any],
    data: Any,  # type: ignore[reportRedeclaration]
) -> tuple[dict[str, Any], str]:
    data: QueryRuleData = data  # type: ignore[reportAssignmentType]  # noqa: PLW0127
    """Extracts the integration fields to schema based on package integrations."""
    package_version, notice = find_latest_compatible_version(package, integration, min_stack, packages_manifest)
    notify_user_if_update_available(data, notice, integration)

    schema = collect_schema_fields(integrations_schemas, package, package_version, integration)
    schema.update(ecs_schema)

    integration_schema = {key: kql.parser.elasticsearch_type_family(value) for key, value in schema.items()}
    return integration_schema, package_version


def notify_user_if_update_available(
    data: Any,  # type: ignore[reportRedeclaration]
    notice: list[str],
    integration: str,
) -> None:
    """Notifies the user if an update is available, only once per integration."""

    data: QueryRuleData = data  # type: ignore[reportAssignmentType]  # noqa: PLW0127

    if notice and data.get("notify", False) and integration not in _notified_integrations:
        # flag to only warn once per integration for available upgrades
        _notified_integrations.add(integration)

        print(f"\n{data.get('name')}")
        print("\n".join(notice))


def collect_schema_fields(
    integrations_schemas: dict[str, Any],
    package: str,
    package_version: str,
    integration: str | None = None,
) -> dict[str, Any]:
    """Collects the schema fields for a given integration."""
    if integration is None:
        return {
            field: value
            for dataset in integrations_schemas[package][package_version]
            if dataset != "jobs"
            for field, value in integrations_schemas[package][package_version][dataset].items()
        }

    if integration not in integrations_schemas[package][package_version]:
        raise ValueError(f"Integration {integration} not found in package {package} version {package_version}")

    return integrations_schemas[package][package_version][integration]


def parse_datasets(datasets: list[str], package_manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Parses datasets into packaged integrations from rule data."""
    packaged_integrations: list[dict[str, Any]] = []
    # FIXME @eric-forte-elastic: evaluate using EventDataset dataclass for parsing # noqa: FIX001, TD001, TD003
    for _value in sorted(datasets):
        # cleanup extra quotes pulled from ast field
        value = _value.strip('"')

        integration = "Unknown"
        if "." in value:
            package, integration = value.split(".", 1)
            # Handle cases where endpoint event datasource needs to be parsed uniquely (e.g endpoint.events.network)
            # as endpoint.network
            if package == "endpoint" and "events" in integration:
                integration = integration.split(".")[1]
        else:
            package = value

        if package in list(package_manifest):
            packaged_integrations.append({"package": package, "integration": integration})
    return packaged_integrations


class SecurityDetectionEngine:
    """Dedicated to Security Detection Engine integration."""

    def __init__(self) -> None:
        self.epr_url = "https://epr.elastic.co/package/security_detection_engine/"

    def load_integration_assets(self, package_version: Version) -> dict[str, Any]:
        """Loads integration assets into memory."""

        epr_package_url = f"{self.epr_url}{package_version!s}/"
        epr_response = requests.get(epr_package_url, timeout=10)
        epr_response.raise_for_status()
        package_obj = epr_response.json()
        zip_url = f"https://epr.elastic.co{package_obj['download']}"
        zip_response = requests.get(zip_url, timeout=30)
        with unzip(zip_response.content) as zip_package:
            asset_file_names = [asset for asset in zip_package.namelist() if "json" in asset]
            return {
                x.split("/")[-1].replace(".json", ""): json.loads(zip_package.read(x).decode("utf-8"))
                for x in asset_file_names
            }

    def keep_latest_versions(
        self,
        assets: dict[str, Any],
        num_versions: int = DEFAULT_MAX_RULE_VERSIONS,
    ) -> dict[str, Any]:
        """Keeps only the latest N versions of each rule to limit historical rule versions in our release package."""

        # Dictionary to hold the sorted list of versions for each base rule ID
        rule_versions: dict[str, list[tuple[int, str]]] = defaultdict(list)

        # Separate rule ID and version, and group by base rule ID
        for key in assets:
            base_id, version = assets[key]["attributes"]["rule_id"], assets[key]["attributes"]["version"]
            version = int(version)  # Convert version to an integer for sorting
            rule_versions[base_id].append((version, key))

        # Dictionary to hold the final assets with only the specified number of latest versions
        filtered_assets: dict[str, Any] = {}

        # Keep only the last/latest num_versions versions for each rule
        # Sort versions and take the last num_versions
        # Add the latest versions of the rule to the filtered assets
        for versions in rule_versions.values():
            latest_versions = sorted(versions, key=lambda x: x[0], reverse=True)[:num_versions]
            for _, key in latest_versions:
                filtered_assets[key] = assets[key]

        return filtered_assets
