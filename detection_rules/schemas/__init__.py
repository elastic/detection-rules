# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
import json
from collections import OrderedDict
from pathlib import Path
from typing import List, Optional
from typing import OrderedDict as OrderedDictType

import jsonschema
from semver import Version

from ..misc import load_current_package_version
from ..utils import cached, get_etc_path, load_etc_dump
from . import definitions
from .rta_schema import validate_rta_mapping
from .stack_compat import get_incompatible_fields

__all__ = (
    "SCHEMA_DIR",
    "definitions",
    "downgrade",
    "get_incompatible_fields",
    "get_min_supported_stack_version",
    "get_stack_schemas",
    "get_stack_versions",
    "validate_rta_mapping",
    "all_versions",
)

SCHEMA_DIR = Path(get_etc_path("api_schemas"))
migrations = {}


def all_versions() -> List[str]:
    """Get all known stack versions."""
    return [str(v) for v in sorted(migrations)]


def migrate(version: str):
    """Decorator to set a migration."""
    # checks that the migrate decorator name is semi-semantic versioned
    # raises validation error from semver if not
    Version.parse(version, optional_minor_and_patch=True)

    def wrapper(f):
        assert version not in migrations
        migrations[version] = f
        return f

    return wrapper


@cached
def get_schema_file(version: Version, rule_type: str) -> dict:
    path = Path(SCHEMA_DIR) / str(version) / f"{version}.{rule_type}.json"

    if not path.exists():
        raise ValueError(f"Unsupported rule type {rule_type}. Unable to downgrade to {version}")

    return json.loads(path.read_text(encoding="utf8"))


def strip_additional_properties(version: Version, api_contents: dict) -> dict:
    """Remove all fields that the target schema doesn't recognize."""

    stripped = {}
    target_schema = get_schema_file(version, api_contents["type"])

    for field, field_schema in target_schema["properties"].items():
        if field in api_contents:
            stripped[field] = api_contents[field]

    # finally, validate against the json schema
    jsonschema.validate(stripped, target_schema)
    return stripped


def strip_non_public_fields(min_stack_version: Version, data_dict: dict) -> dict:
    """Remove all non public fields."""
    for field, version_range in definitions.NON_PUBLIC_FIELDS.items():
        if version_range[0] <= min_stack_version <= (version_range[1] or min_stack_version):
            if field in data_dict:
                del data_dict[field]
    return data_dict


@migrate("7.8")
def migrate_to_7_8(version: Version, api_contents: dict) -> dict:
    """Default migration for 7.8."""
    return strip_additional_properties(version, api_contents)


@migrate("7.9")
def migrate_to_7_9(version: Version, api_contents: dict) -> dict:
    """Default migration for 7.9."""
    return strip_additional_properties(version, api_contents)


@migrate("7.10")
def downgrade_threat_to_7_10(version: Version, api_contents: dict) -> dict:
    """Downgrade the threat mapping changes from 7.11 to 7.10."""
    if "threat" in api_contents:
        v711_threats = api_contents.get("threat", [])
        v710_threats = []

        for threat in v711_threats:
            # drop tactic without threat
            if "technique" not in threat:
                continue

            threat = threat.copy()
            threat["technique"] = [t.copy() for t in threat["technique"]]

            # drop subtechniques
            for technique in threat["technique"]:
                technique.pop("subtechnique", None)

            v710_threats.append(threat)

        api_contents = api_contents.copy()
        api_contents.pop("threat")

        # only add if the array is not empty
        if len(v710_threats) > 0:
            api_contents["threat"] = v710_threats

    # finally, downgrade any additional properties that were added
    return strip_additional_properties(version, api_contents)


@migrate("7.11")
def downgrade_threshold_to_7_11(version: Version, api_contents: dict) -> dict:
    """Remove 7.12 threshold changes that don't impact the rule."""
    if "threshold" in api_contents:
        threshold = api_contents['threshold']
        threshold_field = threshold['field']

        # attempt to convert threshold field to a string
        if len(threshold_field) > 1:
            raise ValueError('Cannot downgrade a threshold rule that has multiple threshold fields defined')

        if threshold.get('cardinality'):
            raise ValueError('Cannot downgrade a threshold rule that has a defined cardinality')

        api_contents = api_contents.copy()
        api_contents["threshold"] = api_contents["threshold"].copy()

        # if cardinality was defined with no field or value
        api_contents['threshold'].pop('cardinality', None)
        api_contents["threshold"]["field"] = api_contents["threshold"]["field"][0]

    # finally, downgrade any additional properties that were added
    return strip_additional_properties(version, api_contents)


@migrate("7.12")
def migrate_to_7_12(version: Version, api_contents: dict) -> dict:
    """Default migration for 7.12."""
    return strip_additional_properties(version, api_contents)


@migrate("7.13")
def downgrade_ml_multijob_713(version: Version, api_contents: dict) -> dict:
    """Convert `machine_learning_job_id` as an array to a string for < 7.13."""
    if "machine_learning_job_id" in api_contents:
        job_id = api_contents["machine_learning_job_id"]

        if isinstance(job_id, list):
            if len(job_id) > 1:
                raise ValueError('Cannot downgrade an ML rule with multiple jobs defined')

            api_contents = api_contents.copy()
            api_contents["machine_learning_job_id"] = job_id[0]

    # finally, downgrade any additional properties that were added
    return strip_additional_properties(version, api_contents)


@migrate("7.14")
def migrate_to_7_14(version: Version, api_contents: dict) -> dict:
    """Default migration for 7.14."""
    return strip_additional_properties(version, api_contents)


@migrate("7.15")
def migrate_to_7_15(version: Version, api_contents: dict) -> dict:
    """Default migration for 7.15."""
    return strip_additional_properties(version, api_contents)


@migrate("7.16")
def migrate_to_7_16(version: Version, api_contents: dict) -> dict:
    """Default migration for 7.16."""
    return strip_additional_properties(version, api_contents)


@migrate("8.0")
def migrate_to_8_0(version: Version, api_contents: dict) -> dict:
    """Default migration for 8.0."""
    return strip_additional_properties(version, api_contents)


@migrate("8.1")
def migrate_to_8_1(version: Version, api_contents: dict) -> dict:
    """Default migration for 8.1."""
    return strip_additional_properties(version, api_contents)


@migrate("8.2")
def migrate_to_8_2(version: Version, api_contents: dict) -> dict:
    """Default migration for 8.2."""
    return strip_additional_properties(version, api_contents)


@migrate("8.3")
def migrate_to_8_3(version: Version, api_contents: dict) -> dict:
    """Default migration for 8.3."""
    return strip_additional_properties(version, api_contents)


@migrate("8.4")
def migrate_to_8_4(version: Version, api_contents: dict) -> dict:
    """Default migration for 8.4."""
    return strip_additional_properties(version, api_contents)


@migrate("8.5")
def migrate_to_8_5(version: Version, api_contents: dict) -> dict:
    """Default migration for 8.5."""
    return strip_additional_properties(version, api_contents)


@migrate("8.6")
def migrate_to_8_6(version: Version, api_contents: dict) -> dict:
    """Default migration for 8.6."""
    return strip_additional_properties(version, api_contents)


@migrate("8.7")
def migrate_to_8_7(version: Version, api_contents: dict) -> dict:
    """Default migration for 8.7."""
    return strip_additional_properties(version, api_contents)


@migrate("8.8")
def migrate_to_8_8(version: Version, api_contents: dict) -> dict:
    """Default migration for 8.8."""
    return strip_additional_properties(version, api_contents)


@migrate("8.9")
def migrate_to_8_9(version: Version, api_contents: dict) -> dict:
    """Default migration for 8.9."""
    return strip_additional_properties(version, api_contents)


@migrate("8.10")
def migrate_to_8_10(version: Version, api_contents: dict) -> dict:
    """Default migration for 8.10."""
    return strip_additional_properties(version, api_contents)


@migrate("8.11")
def migrate_to_8_11(version: Version, api_contents: dict) -> dict:
    """Default migration for 8.11."""
    return strip_additional_properties(version, api_contents)


@migrate("8.12")
def migrate_to_8_12(version: Version, api_contents: dict) -> dict:
    """Default migration for 8.12."""
    return strip_additional_properties(version, api_contents)


@migrate("8.13")
def migrate_to_8_13(version: Version, api_contents: dict) -> dict:
    """Default migration for 8.13."""
    return strip_additional_properties(version, api_contents)


def downgrade(api_contents: dict, target_version: str, current_version: Optional[str] = None) -> dict:
    """Downgrade a rule to a target stack version."""
    from ..packaging import current_stack_version

    if current_version is None:
        current_version = current_stack_version()

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
def load_stack_schema_map() -> dict:
    return load_etc_dump('stack-schema-map.yaml')


@cached
def get_stack_schemas(stack_version: Optional[str] = '0.0.0') -> OrderedDictType[str, dict]:
    """Return all ECS + beats to stack versions for every stack version >= specified stack version and <= package."""
    stack_version = Version.parse(stack_version or '0.0.0', optional_minor_and_patch=True)
    current_package = Version.parse(load_current_package_version(), optional_minor_and_patch=True)

    stack_map = load_stack_schema_map()
    versions = {k: v for k, v in stack_map.items() if
                (((mapped_version := Version.parse(k)) >= stack_version)
                and (mapped_version <= current_package) and v)}  # noqa: W503

    if stack_version > current_package:
        versions[stack_version] = {'beats': 'main', 'ecs': 'master'}

    versions_reversed = OrderedDict(sorted(versions.items(), reverse=True))
    return versions_reversed


def get_stack_versions(drop_patch=False) -> List[str]:
    """Get a list of stack versions supported (for the matrix)."""
    versions = list(load_stack_schema_map())
    if drop_patch:
        abridged_versions = []
        for version in versions:
            abridged, _ = version.rsplit('.', 1)
            abridged_versions.append(abridged)
        return abridged_versions
    else:
        return versions


@cached
def get_min_supported_stack_version() -> Version:
    """Get the minimum defined and supported stack version."""
    stack_map = load_stack_schema_map()
    min_version = min([Version.parse(v) for v in list(stack_map)])
    return min_version
