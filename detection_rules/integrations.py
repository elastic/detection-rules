# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions to support and interact with Kibana integrations."""

import fnmatch
import gzip
import json
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
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
    import zipfile

    from .rule import QueryRuleData, RuleMeta


MANIFEST_FILE_PATH = get_etc_path(["integration-manifests.json.gz"])
DEFAULT_MAX_RULE_VERSIONS = 1
SCHEMA_FILE_PATH = get_etc_path(["integration-schemas.json.gz"])
ECS_ADDITIONS_FILE_PATH = get_etc_path(["integration-ecs-additions.json"])


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


def parse_version_schema(zip_ref: "zipfile.ZipFile", package: str) -> dict[str, Any]:
    """Parse the field files of an EPR package zip into a single version schema."""
    version_schema: dict[str, Any] = {}
    ecs_declared: dict[str, set[str]] = {}

    for file in zip_ref.namelist():
        file_data_bytes = zip_ref.read(file)
        # Check if the file is a match
        if fnmatch.fnmatch(file, "*/fields/*.yml"):
            integration_name = Path(file).parent.parent.name
            version_schema.setdefault(integration_name, {})  # type: ignore[reportUnknownMemberType]
            schema_fields = yaml.safe_load(file_data_bytes)

            # Parse the schema and add to the integration_manifests
            data = flatten_ecs_schema(schema_fields)
            flat_data = {field["name"]: field["type"] for field in data}

            version_schema[integration_name].update(flat_data)  # type: ignore[reportUnknownMemberType]

            if Path(file).name == "ecs.yml":
                # ECS fields the data stream explicitly declares; used to scope query
                # validation to the ECS fields the integration actually populates
                ecs_declared.setdefault(integration_name, set()).update(flat_data)

        # add machine learning jobs to the schema
        if package in [str.lower(x) for x in definitions.MACHINE_LEARNING_PACKAGES] and fnmatch.fnmatch(
            file, "*/ml_module/*ml.json"
        ):
            ml_module = json.loads(file_data_bytes)
            job_ids = [job["id"] for job in ml_module["attributes"]["jobs"]]
            version_schema["jobs"] = job_ids

        del file_data_bytes

    for integration_name, declared in ecs_declared.items():
        version_schema[integration_name]["_ecs_declared"] = sorted(declared)

    # Packages that declare no ECS fields in any data stream rely on the ecs@mappings
    # component template (applied by Fleet to all spec 3.x packages) to inherit every
    # ECS field mapping at index time, so they must be validated against the full ECS schema.
    version_schema["_uses_ecs_mappings"] = not ecs_declared
    return version_schema


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
            existing_version_schema: dict[str, Any] | None = final_integration_schemas.get(package, {}).get(version)  # type: ignore[reportUnknownMemberType]
            if existing_version_schema is not None and "_uses_ecs_mappings" in existing_version_schema:
                continue

            # Download the zip file
            download_url = f"https://epr.elastic.co{manifest['download']}"
            response = requests.get(download_url, timeout=30)
            response.raise_for_status()

            # Open the zip file
            with unzip(response.content) as zip_ref:
                final_integration_schemas[package][version] = parse_version_schema(zip_ref, package)

    # Write the final integration schemas to disk
    with gzip.open(SCHEMA_FILE_PATH, "w") as schema_file:
        schema_file_bytes = json.dumps(final_integration_schemas).encode("utf-8")
        _ = schema_file.write(schema_file_bytes)

    print(f"final integrations manifests dumped: {SCHEMA_FILE_PATH}")


def _parse_clause(clause: str) -> tuple[Version, Version | None]:
    """Parse a single AND'd clause of npm-style range tokens into [lo, hi) bounds.

    hi is None when the clause has no upper bound. Supports the subset of
    npm semver currently emitted by EPR conditions.kibana.version strings:
    ^X.Y.Z, ~X.Y.Z, >=X.Y.Z, >X.Y.Z, <=X.Y.Z, <X.Y.Z,
    =X.Y.Z, and bare X.Y.Z. Unsupported tokens raise ValueError so
    we fail loudly if EPR's grammar grows.
    """
    lo = Version(0, 0, 0)
    hi: Version | None = None

    def tighten_hi(current: Version | None, candidate: Version) -> Version:
        return candidate if current is None else min(current, candidate)

    for token in clause.strip().split():
        if not token:
            continue
        if token.startswith("^"):
            base = Version.parse(token[1:])
            if base.major == 0:
                raise ValueError(f"caret on 0.x kibana version is unsupported: {token!r}")
            lo = max(lo, base)
            hi = tighten_hi(hi, Version(base.major + 1, 0, 0))
        elif token.startswith("~"):
            base = Version.parse(token[1:])
            lo = max(lo, base)
            hi = tighten_hi(hi, Version(base.major, base.minor + 1, 0))
        elif token.startswith(">="):
            lo = max(lo, Version.parse(token[2:]))
        elif token.startswith("<="):
            hi = tighten_hi(hi, Version.parse(token[2:]).bump_patch())
        elif token.startswith(">"):
            lo = max(lo, Version.parse(token[1:]).bump_patch())
        elif token.startswith("<"):
            hi = tighten_hi(hi, Version.parse(token[1:]))
        elif token.startswith("="):
            exact = Version.parse(token[1:])
            lo = max(lo, exact)
            hi = tighten_hi(hi, exact.bump_patch())
        elif token[0].isdigit():
            exact = Version.parse(token)
            lo = max(lo, exact)
            hi = tighten_hi(hi, exact.bump_patch())
        else:
            raise ValueError(f"unsupported kibana version token: {token!r}")
    return lo, hi


def _parse_kibana_range(version_requirement: str) -> list[tuple[Version, Version | None]]:
    """Parse an EPR conditions.kibana.version string into a list of [lo, hi) clauses.

    Clauses separated by || are OR'd; whitespace-separated tokens within a
    clause are AND'd.
    """
    return [_parse_clause(c) for c in version_requirement.split("||")]


def _satisfies_kibana_range(stack: Version, version_requirement: str) -> bool:
    """Return True iff stack satisfies the EPR conditions.kibana.version string."""
    return any(lo <= stack and (hi is None or stack < hi) for lo, hi in _parse_kibana_range(version_requirement))


def find_latest_integration_patch_for_minor(packages: Iterable[str], major: int, minor: int) -> int:
    """Find the latest stack patch integration packages need for a major.minor."""
    # stack-schema-map keys stacks at MAJOR.MINOR.0, but an integration may gate its latest
    # package (and newly-added data streams) behind a later patch (e.g. azure ~8.19.10).
    # Resolving against the literal .0 falls back to an older package that predates the
    # stream. Return the latest patch a package gates on for the minor.
    #
    # Track the *newest* package version's floor (not the max floor across all versions):
    # Fleet always installs the latest compatible package, so that floor is the patch a
    # stack actually needs. A newer package occasionally lowers its floor (e.g. apm 7.16.1
    # gates ^7.16.1 but the newer 7.16.2 gates ^7.16.0); honoring the newest version
    # matches what Fleet installs rather than an older, higher floor.
    manifests = load_integrations_manifests()
    latest_patch = 0
    for package in packages:
        latest_package_version: Version | None = None
        latest_package_patch = 0
        for package_version, manifest in manifests.get(package, {}).items():
            version_requirement = manifest.get("conditions", {}).get("kibana", {}).get("version")
            if not version_requirement:
                continue
            try:
                clauses = _parse_kibana_range(version_requirement)
            except ValueError:
                # Skip manifests whose kibana condition uses tokens we cannot parse.
                continue
            floors = [lo.patch for lo, _ in clauses if lo.major == major and lo.minor == minor]
            if not floors:
                continue
            parsed_package_version = Version.parse(package_version)
            if latest_package_version is None or parsed_package_version > latest_package_version:
                latest_package_version = parsed_package_version
                latest_package_patch = max(floors)
        latest_patch = max(latest_patch, latest_package_patch)
    return latest_patch


# Sentinel written by parse_datasets when a rule indexes a package but not a data stream.
UNKNOWN_PACKAGE_INTEGRATION = "Unknown"
# Stack versions at/above this use >= for related_integrations.version (caret below).
RELATED_INTEGRATION_GTE_OPERATOR_MIN_STACK = Version(9, 5, 0)


def _package_version_has_integration(
    version: str,
    integration: str,
    package_schemas: dict[str, Any],
) -> bool:
    """Return True when schema data is absent or includes the integration/data stream."""
    if version not in package_schemas:
        return True
    return integration in package_schemas[version]


def _find_least_compatible_for_stack(
    stack_version: Version,
    integration_manifests: dict[str, Any],
    integration: str | None = None,
    package_schemas: dict[str, Any] | None = None,
) -> str | None:
    """Stack-dependent least compatible integration version (pre-#5601 behavior)."""
    major_versions = sorted(
        {Version.parse(manifest_version).major for manifest_version in integration_manifests},
        reverse=True,
    )
    for max_major in major_versions:
        major_integration_manifests = {
            version: manifest
            for version, manifest in integration_manifests.items()
            if Version.parse(version).major == max_major
        }
        for version, manifest in sorted(major_integration_manifests.items(), key=lambda x: Version.parse(x[0])):
            version_requirement = manifest["conditions"]["kibana"]["version"]
            if not _satisfies_kibana_range(stack_version, version_requirement):
                continue
            if (
                integration
                and package_schemas is not None
                and not _package_version_has_integration(version, integration, package_schemas)
            ):
                continue
            return version
    return None


@dataclass(frozen=True)
class RelatedIntegrationVersion:
    """Resolved related_integrations.version value for the current package stack."""

    expression: str
    manifest_versions: tuple[str, ...]


class IntegrationVersionNotFoundError(ValueError):
    """Raised when a package has no compatible version for the requested stack/integration."""


def _related_integration_version_operator(stack_version: Version) -> str:
    """Return the semver operator for related_integrations.version on the current stack.

    Stack ≥ 9.5 uses ``>=``; older stacks keep caret ranges. The
    ``related_integrations_gte`` emit transform still rewrites any remaining
    ``^`` values on ≥ 9.5 so export/view/package paths stay consistent.
    """
    if stack_version >= RELATED_INTEGRATION_GTE_OPERATOR_MIN_STACK:
        return ">="
    return "^"


def resolve_related_integration_version(
    package: str,
    packages_manifest: dict[str, Any],
    integration: str | None = None,
) -> RelatedIntegrationVersion:
    """Return the current-stack related_integrations.version expression."""
    package_manifest = packages_manifest.get(package)
    if package_manifest is None:
        raise ValueError(f"Package {package} not found in manifest.")

    package_schemas: dict[str, Any] = {}
    if integration:
        package_schemas = load_integrations_schemas().get(package, {})

    integration_manifests = dict(sorted(package_manifest.items(), key=lambda x: Version.parse(x[0])))
    current_stack = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
    manifest_version = _find_least_compatible_for_stack(
        current_stack, integration_manifests, integration, package_schemas
    )
    if manifest_version is None:
        package_label = f"{package}:{integration}" if integration else package
        raise IntegrationVersionNotFoundError(f"no compatible version for integration {package_label}")

    operator = _related_integration_version_operator(current_stack)
    return RelatedIntegrationVersion(expression=f"{operator}{manifest_version}", manifest_versions=(manifest_version,))


def find_latest_compatible_version(
    package: str,
    integration: str,
    rule_stack_version: Version,
    packages_manifest: dict[str, Any],
    package_schemas: dict[str, Any] | None = None,
) -> tuple[str, list[str]]:
    """Finds latest compatible version for specified integration based on stack version supplied."""

    if not package:
        raise ValueError("Package must be specified")

    package_manifest = packages_manifest.get(package)
    if package_manifest is None:
        raise ValueError(f"Package {package} not found in manifest.")

    # Converts the dict keys (version numbers) to Version objects for proper sorting (descending)
    integration_manifests = sorted(package_manifest.items(), key=lambda x: Version.parse(x[0]), reverse=True)
    notice: list[str] = [""]
    newest_skipped: tuple[str, Version] | None = None

    for version, manifest in integration_manifests:
        kibana_conditions = manifest.get("conditions", {}).get("kibana", {})
        version_requirement = kibana_conditions.get("version")
        if not version_requirement:
            raise ValueError(f"Manifest for {package}:{integration} version {version} is missing conditions.")

        if _satisfies_kibana_range(rule_stack_version, version_requirement):
            if (
                integration
                and package_schemas is not None
                and not _package_version_has_integration(version, integration, package_schemas)
            ):
                continue
            if newest_skipped is not None:
                skipped_version, skipped_floor = newest_skipped
                integration_label = f" {integration.strip()}" if integration else ""
                notice = [
                    f"There is a new integration {package}{integration_label} version {skipped_version} available!",
                    f"Update the rule min_stack version from {rule_stack_version} to "
                    f"{skipped_floor} if using new features in this latest version.",
                ]
            return version, notice

        # Track the newest manifest we had to skip so the notice can still
        # point the reader at the most recent incompatible version and its floor.
        if newest_skipped is None:
            clauses = _parse_kibana_range(version_requirement)
            floor = min(lo for lo, _ in clauses)
            newest_skipped = (version, floor)

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
            parsed_stack_version = Version.parse(stack_version)
            patch_floor = find_latest_integration_patch_for_minor(
                {pk_int["package"] for pk_int in package_integrations},
                parsed_stack_version.major,
                parsed_stack_version.minor,
            )
            min_stack = Version(
                parsed_stack_version.major,
                parsed_stack_version.minor,
                max(parsed_stack_version.patch, patch_floor),
            )

            ecs_schema = ecs.flatten_multi_fields(ecs.get_schema(ecs_version, name="ecs_flat"))

            for pk_int in package_integrations:
                package = pk_int["package"]
                integration = pk_int["integration"]

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
    package_schemas = integrations_schemas.get(package, {}) if integration else None
    package_version, notice = find_latest_compatible_version(
        package,
        integration,
        min_stack,
        packages_manifest,
        package_schemas=package_schemas,
    )
    notify_user_if_update_available(data, notice, integration)

    schema = collect_schema_fields(integrations_schemas, package, package_version, integration)

    if integration_declares_ecs_fields(integrations_schemas, package, package_version, integration):
        # The integration explicitly enumerates the ECS fields it populates (per data stream
        # ecs.yml), so validate strictly against those instead of the entire ECS schema.
        # Pipeline-injected fields that cannot be determined statically come from the
        # integration-ecs-additions.json override file.
        additions = get_integration_ecs_additions(package, integration)
        schema.update({field: ecs_schema[field] for field in additions if field in ecs_schema})
    else:
        # The integration inherits all ECS field mappings via the ecs@mappings component
        # template (or the cached schema predates ECS scoping), so any ECS field is valid.
        schema.update(ecs_schema)

    integration_schema = {key: kql.parser.elasticsearch_type_family(value) for key, value in schema.items()}
    return integration_schema, package_version


def integration_declares_ecs_fields(
    integrations_schemas: dict[str, Any],
    package: str,
    package_version: str,
    integration: str | None = None,
) -> bool:
    """Return True when the package version explicitly declares the ECS fields it populates.

    Data streams declare their ECS fields in per-data-stream ecs.yml files, captured in the
    cached schema as `_ecs_declared`. Packages without any declarations (e.g. cloud_defend,
    endpoint) inherit every ECS field at index time via the ecs@mappings component template
    and must keep full-ECS validation. Cached schemas built before this metadata existed
    also return False, preserving the historical behavior until the cache is regenerated.
    """
    version_schema: dict[str, Any] = integrations_schemas.get(package, {}).get(package_version, {})
    if version_schema.get("_uses_ecs_mappings") is not False:
        # True -> relies on ecs@mappings; missing -> legacy cache format
        return False
    if integration:
        dataset_schema = version_schema.get(integration, {})
        return isinstance(dataset_schema, dict) and bool(dataset_schema.get("_ecs_declared"))  # type: ignore[reportUnknownMemberType]
    # package-wide query: only strict when every data stream declares its ECS fields,
    # otherwise an undeclared data stream could produce false validation failures
    dataset_schemas: list[dict[str, Any]] = [
        value
        for key, value in version_schema.items()
        if key != "jobs" and not key.startswith("_") and isinstance(value, dict)
    ]
    return bool(dataset_schemas) and all(dataset.get("_ecs_declared") for dataset in dataset_schemas)


@cached
def load_integration_ecs_additions() -> dict[str, Any]:
    """Load the per-integration override file for ECS fields populated outside field definitions."""
    if not ECS_ADDITIONS_FILE_PATH.exists():
        return {}
    return json.loads(ECS_ADDITIONS_FILE_PATH.read_text())


def get_integration_ecs_additions(package: str, integration: str | None = None) -> set[str]:
    """Get ECS fields a package populates outside its field definitions (e.g. ingest pipelines)."""
    additions_config = load_integration_ecs_additions()
    # fields the Elastic Agent / Fleet final pipeline stamps on every shipped event
    additions: set[str] = set(additions_config.get("_all_packages", []))
    package_additions = additions_config.get(package, {})
    additions.update(package_additions.get("_all", []))
    for key, fields_ in package_additions.items():
        if key == "_all":
            continue
        if integration is None or key == integration:
            additions.update(fields_)
    return additions


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
            if dataset != "jobs" and not dataset.startswith("_")
            for field, value in integrations_schemas[package][package_version][dataset].items()
            if not field.startswith("_")
        }

    if integration not in integrations_schemas[package][package_version]:
        raise ValueError(f"Integration {integration} not found in package {package} version {package_version}")

    return {
        field: value
        for field, value in integrations_schemas[package][package_version][integration].items()
        if not field.startswith("_")
    }


def parse_datasets(datasets: list[str], package_manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Parses datasets into packaged integrations from rule data."""
    packaged_integrations: list[dict[str, Any]] = []
    # FIXME @eric-forte-elastic: evaluate using EventDataset dataclass for parsing # noqa: FIX001, TD001, TD003
    for _value in sorted(datasets):
        # cleanup extra quotes pulled from ast field
        value = _value.strip('"')

        integration = UNKNOWN_PACKAGE_INTEGRATION
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
        assets: dict[str, dict[str, Any]],
        num_versions: int = DEFAULT_MAX_RULE_VERSIONS,
    ) -> dict[str, Any]:
        """Keeps only the latest N versions of each rule to limit historical rule versions in our release package."""

        # Dictionary to hold the sorted list of versions for each base rule ID
        rule_versions: dict[str, list[tuple[int, str]]] = defaultdict(list)

        # Only version-limit assets that look like rules (have attributes.rule_id and attributes.version).
        # Other JSON assets in the package (e.g. manifest) are skipped; add_historical_rules expects only rules.
        filtered_assets: dict[str, Any] = {}

        for key, asset in assets.items():
            attrs = asset.get("attributes")
            if not attrs or "rule_id" not in attrs or "version" not in attrs:
                continue
            base_id = attrs["rule_id"]
            version = int(attrs["version"])
            rule_versions[base_id].append((version, key))

        # Keep only the last/latest num_versions versions for each rule
        # Sort versions and take the last num_versions
        # Add the latest versions of the rule to the filtered assets
        for versions in rule_versions.values():
            latest_versions = sorted(versions, key=lambda x: x[0], reverse=True)[:num_versions]
            for _, key in latest_versions:
                filtered_assets[key] = assets[key]

        return filtered_assets
