# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
import json
from collections import OrderedDict
from collections import OrderedDict as OrderedDictType
from collections.abc import Callable
from typing import Any

import jsonschema
from semver import Version

from detection_rules.config import load_current_package_version, parse_rules_config
from detection_rules.utils import cached, get_etc_path

from . import definitions
from .stack_compat import get_incompatible_fields

__all__ = (
    "SCHEMA_DIR",
    "all_versions",
    "definitions",
    "downgrade",
    "get_incompatible_fields",
    "get_min_supported_stack_version",
    "get_stack_schemas",
    "get_stack_versions",
)

RULES_CONFIG = parse_rules_config()
SCHEMA_DIR = get_etc_path(["api_schemas"])

MigratedFuncT = Callable[..., Any]

migrations: dict[str, MigratedFuncT] = {}


def all_versions() -> list[str]:
    """Get all known stack versions."""
    return [str(v) for v in sorted(migrations, key=lambda x: Version.parse(x, optional_minor_and_patch=True))]


def migrate(version: str) -> Callable[[MigratedFuncT], MigratedFuncT]:
    """Decorator to set a migration."""
    # checks that the migrate decorator name is semi-semantic versioned
    # raises validation error from semver if not
    _ = Version.parse(version, optional_minor_and_patch=True)

    def wrapper(f: MigratedFuncT) -> MigratedFuncT:
        if version in migrations:
            raise ValueError("Version found in migrations")
        migrations[version] = f
        return f

    return wrapper


@cached
def get_schema_file(version: Version, rule_type: str) -> dict[str, Any]:
    path = SCHEMA_DIR / str(version) / f"{version}.{rule_type}.json"

    if not path.exists():
        raise ValueError(f"Unsupported rule type {rule_type}. Unable to downgrade to {version}")

    return json.loads(path.read_text(encoding="utf8"))


def strip_additional_properties(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Remove all fields that the target schema doesn't recognize."""

    stripped: dict[str, Any] = {}
    target_schema = get_schema_file(version, api_contents["type"])

    for field in target_schema["properties"]:
        if field in api_contents:
            stripped[field] = api_contents[field]

    # finally, validate against the json schema
    jsonschema.validate(stripped, target_schema)
    return stripped


def strip_non_public_fields(min_stack_version: Version, data_dict: dict[str, Any]) -> dict[str, Any]:
    """Remove all non public fields."""
    for field, version_range in definitions.NON_PUBLIC_FIELDS.items():
        if version_range[0] <= min_stack_version <= (version_range[1] or min_stack_version):
            data_dict.pop(field, None)
    return data_dict


@migrate("7.8")
def migrate_to_7_8(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 7.8."""
    return strip_additional_properties(version, api_contents)


@migrate("7.9")
def migrate_to_7_9(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 7.9."""
    return strip_additional_properties(version, api_contents)


@migrate("7.10")
def downgrade_threat_to_7_10(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Downgrade the threat mapping changes from 7.11 to 7.10."""
    if "threat" in api_contents:
        v711_threats = api_contents.get("threat", [])
        v710_threats: list[Any] = []

        for threat in v711_threats:
            # drop tactic without threat
            if "technique" not in threat:
                continue

            threat_copy = threat.copy()
            threat_copy["technique"] = [t.copy() for t in threat_copy["technique"]]

            # drop subtechniques
            for technique in threat_copy["technique"]:
                technique.pop("subtechnique", None)

            v710_threats.append(threat_copy)

        api_contents = api_contents.copy()
        api_contents.pop("threat")

        # only add if the array is not empty
        if len(v710_threats) > 0:
            api_contents["threat"] = v710_threats

    # finally, downgrade any additional properties that were added
    return strip_additional_properties(version, api_contents)


@migrate("7.11")
def downgrade_threshold_to_7_11(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Remove 7.12 threshold changes that don't impact the rule."""
    if "threshold" in api_contents:
        threshold = api_contents["threshold"]
        threshold_field = threshold["field"]

        # attempt to convert threshold field to a string
        if len(threshold_field) > 1:
            raise ValueError("Cannot downgrade a threshold rule that has multiple threshold fields defined")

        if threshold.get("cardinality"):
            raise ValueError("Cannot downgrade a threshold rule that has a defined cardinality")

        api_contents = api_contents.copy()
        api_contents["threshold"] = api_contents["threshold"].copy()

        # if cardinality was defined with no field or value
        api_contents["threshold"].pop("cardinality", None)
        api_contents["threshold"]["field"] = api_contents["threshold"]["field"][0]

    # finally, downgrade any additional properties that were added
    return strip_additional_properties(version, api_contents)


@migrate("7.12")
def migrate_to_7_12(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 7.12."""
    return strip_additional_properties(version, api_contents)


@migrate("7.13")
def downgrade_ml_multijob_713(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Convert `machine_learning_job_id` as an array to a string for < 7.13."""
    if "machine_learning_job_id" in api_contents:
        job_id = api_contents["machine_learning_job_id"]

        if isinstance(job_id, list):
            if len(job_id) > 1:  # type: ignore[reportUnknownArgumentType]
                raise ValueError("Cannot downgrade an ML rule with multiple jobs defined")

            api_contents = api_contents.copy()
            api_contents["machine_learning_job_id"] = job_id[0]

    # finally, downgrade any additional properties that were added
    return strip_additional_properties(version, api_contents)


@migrate("7.14")
def migrate_to_7_14(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 7.14."""
    return strip_additional_properties(version, api_contents)


@migrate("7.15")
def migrate_to_7_15(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 7.15."""
    return strip_additional_properties(version, api_contents)


@migrate("7.16")
def migrate_to_7_16(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 7.16."""
    return strip_additional_properties(version, api_contents)


@migrate("8.0")
def migrate_to_8_0(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.0."""
    return strip_additional_properties(version, api_contents)


@migrate("8.1")
def migrate_to_8_1(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.1."""
    return strip_additional_properties(version, api_contents)


@migrate("8.2")
def migrate_to_8_2(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.2."""
    return strip_additional_properties(version, api_contents)


@migrate("8.3")
def migrate_to_8_3(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.3."""
    return strip_additional_properties(version, api_contents)


@migrate("8.4")
def migrate_to_8_4(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.4."""
    return strip_additional_properties(version, api_contents)


@migrate("8.5")
def migrate_to_8_5(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.5."""
    return strip_additional_properties(version, api_contents)


@migrate("8.6")
def migrate_to_8_6(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.6."""
    return strip_additional_properties(version, api_contents)


@migrate("8.7")
def migrate_to_8_7(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.7."""
    return strip_additional_properties(version, api_contents)


@migrate("8.8")
def migrate_to_8_8(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.8."""
    return strip_additional_properties(version, api_contents)


@migrate("8.9")
def migrate_to_8_9(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.9."""
    return strip_additional_properties(version, api_contents)


@migrate("8.10")
def migrate_to_8_10(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.10."""
    return strip_additional_properties(version, api_contents)


@migrate("8.11")
def migrate_to_8_11(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.11."""
    return strip_additional_properties(version, api_contents)


@migrate("8.12")
def migrate_to_8_12(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.12."""
    return strip_additional_properties(version, api_contents)


@migrate("8.13")
def migrate_to_8_13(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.13."""
    return strip_additional_properties(version, api_contents)


@migrate("8.14")
def migrate_to_8_14(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.14."""
    return strip_additional_properties(version, api_contents)


@migrate("8.15")
def migrate_to_8_15(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.15."""
    return strip_additional_properties(version, api_contents)


@migrate("8.16")
def migrate_to_8_16(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.16."""
    return strip_additional_properties(version, api_contents)


@migrate("8.17")
def migrate_to_8_17(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.17."""
    return strip_additional_properties(version, api_contents)


@migrate("8.18")
def migrate_to_8_18(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.18."""
    return strip_additional_properties(version, api_contents)


@migrate("8.19")
def migrate_to_8_19(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 8.19."""
    return strip_additional_properties(version, api_contents)


@migrate("9.0")
def migrate_to_9_0(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 9.0."""
    return strip_additional_properties(version, api_contents)


@migrate("9.1")
def migrate_to_9_1(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 9.1."""
    return strip_additional_properties(version, api_contents)


@migrate("9.2")
def migrate_to_9_2(version: Version, api_contents: dict[str, Any]) -> dict[str, Any]:
    """Default migration for 9.2."""
    return strip_additional_properties(version, api_contents)


def downgrade(
    api_contents: dict[str, Any], target_version: str, current_version_val: str | None = None
) -> dict[str, Any]:
    """Downgrade a rule to a target stack version."""
    from ..packaging import current_stack_version  # noqa: TID252

    current_version = current_version_val or current_stack_version()

    current = Version.parse(current_version, optional_minor_and_patch=True)
    target = Version.parse(target_version, optional_minor_and_patch=True)

    # get all the versions between current_semver and target_semver
    if target.major != current.major:
        raise ValueError(f"Cannot backport to major version {target.major}")

    for minor in reversed(range(target.minor, current.minor)):
        version = f"{target.major}.{minor}"
        if version not in migrations:
            raise ValueError(f"Missing migration for {target_version}")

        api_contents = migrations[str(version)](version, api_contents)

    return api_contents


@cached
def load_stack_schema_map() -> dict[str, Any]:
    return RULES_CONFIG.stack_schema_map


@cached
def get_stack_schemas(stack_version_val: str | None = "0.0.0") -> OrderedDictType[str, dict[str, Any]]:
    """
    Return all ECS, beats, and custom stack versions for every stack version.
    Only versions >= specified stack version and <= package are returned.
    """
    stack_version = Version.parse(stack_version_val or "0.0.0", optional_minor_and_patch=True)
    current_package = Version.parse(load_current_package_version(), optional_minor_and_patch=True)

    stack_map = load_stack_schema_map()
    versions = {
        k: v
        for k, v in stack_map.items()
        if (((mapped_version := Version.parse(k)) >= stack_version) and (mapped_version <= current_package) and v)
    }

    if stack_version > current_package:
        versions[stack_version] = {"beats": "main", "ecs": "master"}

    return OrderedDict(sorted(versions.items(), reverse=True))


def get_stack_versions(drop_patch: bool = False) -> list[str]:
    """Get a list of stack versions supported (for the matrix)."""
    versions = list(load_stack_schema_map())
    if drop_patch:
        abridged_versions: list[str] = []
        for version in versions:
            abridged, _ = version.rsplit(".", 1)
            abridged_versions.append(abridged)
        return abridged_versions
    return versions


def get_latest_stack_version(drop_patch: bool = False) -> str:
    """Get the latest defined and supported stack version."""
    parsed_versions = [Version.parse(version) for version in get_stack_versions(drop_patch=drop_patch)]
    return str(max(parsed_versions))


@cached
def get_min_supported_stack_version() -> Version:
    """Get the minimum defined and supported stack version."""
    stack_map = load_stack_schema_map()
    return min([Version.parse(v) for v in list(stack_map)])
