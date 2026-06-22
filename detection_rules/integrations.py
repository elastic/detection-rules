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
from .schemas import definitions, get_stack_versions
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


def _parse_clause(clause: str) -> tuple[Version, Version | None]:
    """Parse a single AND'd clause of npm-style range tokens into ``[lo, hi)`` bounds.

    ``hi`` is ``None`` when the clause has no upper bound. Supports the subset of
    npm semver currently emitted by EPR ``conditions.kibana.version`` strings:
    ``^X.Y.Z``, ``~X.Y.Z``, ``>=X.Y.Z``, ``>X.Y.Z``, ``<=X.Y.Z``, ``<X.Y.Z``,
    ``=X.Y.Z``, and bare ``X.Y.Z``. Unsupported tokens raise ``ValueError`` so
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
    """Parse an EPR ``conditions.kibana.version`` string into a list of ``[lo, hi)`` clauses.

    Clauses separated by ``||`` are OR'd; whitespace-separated tokens within a
    clause are AND'd.
    """
    return [_parse_clause(c) for c in version_requirement.split("||")]


def _satisfies_kibana_range(stack: Version, version_requirement: str) -> bool:
    """Return True iff ``stack`` satisfies the EPR ``conditions.kibana.version`` string."""
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


# Sentinel written by ``parse_datasets`` when a rule indexes a package but not a data stream.
UNKNOWN_PACKAGE_INTEGRATION = "Unknown"

# Cap majors walked for unbounded Kibana clauses (``>=X.Y.Z``). Intersection with
# ``_shipped_stack_majors()`` keeps only backport lines we ship rules to.
_MAX_UNBOUNDED_STACK_MAJOR_SPAN = 10


def _major_has_compatible_stack(major: int, version_requirement: str) -> bool:
    """Return True iff the Kibana range overlaps some stack in [major.0.0, (major+1).0.0)."""
    major_lo = Version(major, 0, 0)
    major_hi = Version(major + 1, 0, 0)
    return any(lo < major_hi and (hi is None or hi > major_lo) for lo, hi in _parse_kibana_range(version_requirement))


def _package_version_has_integration(
    version: str,
    integration: str,
    package_schemas: dict[str, Any],
) -> bool:
    """Return True when schema data is absent or includes the integration/data stream."""
    if version not in package_schemas:
        return True
    return integration in package_schemas[version]


def _majors_overlapping_kibana_clause(
    lo: Version,
    hi: Version | None,
    version_requirement: str,
) -> list[int]:
    """Return stack majors whose [M.0.0, (M+1).0.0) band intersects the parsed clause bounds."""
    if hi is not None:
        majors_to_check: list[int] = []
        major = lo.major
        while Version(major, 0, 0) < hi:
            majors_to_check.append(major)
            major += 1
        return majors_to_check

    # Unbounded upper (``>=``, ``>``): walk forward while the major still overlaps.
    majors_to_check: list[int] = []
    major = lo.major
    while major <= lo.major + _MAX_UNBOUNDED_STACK_MAJOR_SPAN and _major_has_compatible_stack(
        major, version_requirement
    ):
        majors_to_check.append(major)
        major += 1
    return majors_to_check


def _stack_majors_supported_by_package(integration_manifests: dict[str, Any]) -> set[int]:
    """Collect Kibana stack majors that any manifest in the package can serve."""
    stack_majors: set[int] = set()
    for manifest in integration_manifests.values():
        version_requirement = manifest["conditions"]["kibana"]["version"]
        for lo, hi in _parse_kibana_range(version_requirement):
            for major in _majors_overlapping_kibana_clause(lo, hi, version_requirement):
                stack_majors.add(major)
    return stack_majors


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
class CompatibleVersionRange:
    """Stack-invariant related integration compatibility range."""

    range: str
    anchors: tuple[str, ...]
    forward_anchor: str


def _build_compatible_version_range(anchors: list[str]) -> CompatibleVersionRange:
    """Build a CompatibleVersionRange from manifest-backed anchor versions."""
    if not anchors:
        raise ValueError("anchors must not be empty")

    sorted_anchors = tuple(sorted(set(anchors), key=Version.parse))
    top_major = max(Version.parse(anchor).major for anchor in sorted_anchors)
    # Forward sentinel for the next integration major (no manifest entry yet).
    forward_anchor = f"{top_major + 1}.0.0"
    range_parts = [f"^{anchor}" for anchor in sorted_anchors] + [f"^{forward_anchor}"]
    return CompatibleVersionRange(
        range=" || ".join(range_parts),
        anchors=sorted_anchors,
        forward_anchor=forward_anchor,
    )


@cached
def _shipped_stack_majors() -> set[int]:
    """Stack majors we ship prebuilt rules to (from the stack-schema-map backport lines)."""
    return {Version.parse(version).major for version in get_stack_versions()}


def minimum_schema_package_version(
    package: str,
    integration: str,
    integration_schemas: dict[str, Any],
) -> str | None:
    """Return the oldest package version whose schema includes integration, if any."""
    package_schemas = integration_schemas.get(package)
    if not package_schemas:
        return None

    for version in sorted(package_schemas, key=Version.parse):
        if integration in package_schemas[version]:
            return version
    return None


def apply_schema_version_floor(
    result: CompatibleVersionRange,
    schema_floor: str,
) -> CompatibleVersionRange:
    """Raise anchors in the schema floor's package major when below schema_floor."""
    floor_version = Version.parse(schema_floor)
    floor_major = floor_version.major
    bumped_anchors: list[str] = []

    for anchor in result.anchors:
        anchor_version = Version.parse(anchor)
        if anchor_version.major == floor_major and anchor_version < floor_version:
            continue
        bumped_anchors.append(anchor)

    if not any(Version.parse(anchor).major == floor_major for anchor in bumped_anchors):
        bumped_anchors.append(schema_floor)

    bumped_tuple = tuple(sorted(bumped_anchors, key=Version.parse))
    if bumped_tuple == result.anchors:
        return result

    return _build_compatible_version_range(list(bumped_tuple))


def _collect_compatible_anchors(
    integration_manifests: dict[str, Any],
    stack_majors: set[int],
    integration: str | None,
    package_schemas: dict[str, Any],
) -> list[str]:
    """Oldest compatible integration version per shipped stack version line."""
    anchors: list[str] = []
    for stack_version_str in get_stack_versions():
        stack_version = Version.parse(stack_version_str)
        if stack_version.major not in stack_majors:
            continue
        anchor = _find_least_compatible_for_stack(
            stack_version,
            integration_manifests,
            integration,
            package_schemas,
        )
        if anchor and anchor not in anchors:
            anchors.append(anchor)
    return anchors


def _integration_schema_floor(
    package: str,
    integration: str | None,
    package_schemas: dict[str, Any],
) -> str | None:
    """Oldest package version whose schema includes integration, when schemas are loaded."""
    if not integration or not package_schemas:
        return None
    return minimum_schema_package_version(package, integration, {package: package_schemas})


def find_compatible_version_range(
    package: str,
    packages_manifest: dict[str, Any],
    integration: str | None = None,
) -> CompatibleVersionRange:
    """Return a stack-invariant OR'd caret range for related_integrations.version."""
    # One anchor per shipped stack version line (no build-time stack), OR'd carets, forward sentinel.
    # With integration set, filter by integration-schemas when present (data-stream floor).
    package_manifest = packages_manifest.get(package)
    if package_manifest is None:
        raise ValueError(f"Package {package} not found in manifest.")

    package_schemas: dict[str, Any] = {}
    if integration:
        package_schemas = load_integrations_schemas().get(package, {})
    schema_floor = _integration_schema_floor(package, integration, package_schemas)

    integration_manifests = dict(sorted(package_manifest.items(), key=lambda x: Version.parse(x[0])))
    stack_majors = _stack_majors_supported_by_package(integration_manifests) & _shipped_stack_majors()

    if not stack_majors:
        raise ValueError(f"no compatible version for integration package {package}")

    anchors = _collect_compatible_anchors(integration_manifests, stack_majors, integration, package_schemas)

    if not anchors:
        if schema_floor:
            baseline = find_compatible_version_range(package, packages_manifest)
            return apply_schema_version_floor(baseline, schema_floor)
        package_label = f"{package}:{integration}" if integration else package
        raise ValueError(f"no compatible version for integration {package_label}")

    result = _build_compatible_version_range(anchors)
    if schema_floor:
        result = apply_schema_version_floor(result, schema_floor)
    return result


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
