# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
import json
import jsonschema

from .rta_schema import validate_rta_mapping
from ..semver import Version
from . import definitions
from pathlib import Path


__all__ = (
    "SCHEMA_DIR",
    "definitions",
    "downgrade",
    "validate_rta_mapping",
    "all_versions",
)

SCHEMA_DIR = Path(__file__).absolute().parent.parent.parent / "etc" / "api_schemas"
migrations = {}


def all_versions():
    """Get all known stack versions."""
    return [str(v) for v in sorted(migrations)]


def migrate(version):
    """Decorator to set a migration."""
    version = Version(version)

    def wrapper(f):
        assert version not in migrations
        migrations[version] = f
        return f

    return wrapper


@migrate("7.8")
@migrate("7.9")
@migrate("7.12")
def strip_additional_properties(version: Version, api_contents: dict) -> dict:
    """Remove all fields that the target schema doesn't recognize."""
    rule_type = api_contents["type"]
    stack_dir = Path(SCHEMA_DIR) / str(version)
    schema_file = stack_dir / f"{version}.{rule_type}.json"

    if not schema_file.exists():
        raise ValueError(f"Unsupported rule type {rule_type}")

    target_schema = json.loads(schema_file.read_text(encoding="utf8"))
    stripped = {}

    for field, field_schema in target_schema["properties"].items():
        if field in api_contents:
            stripped[field] = api_contents[field]

    # finally, validate against the json schema
    jsonschema.validate(stripped, target_schema)
    return stripped


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

        if threshold.get('cardinality', {}).get('field') or threshold.get('cardinality', {}).get('value'):
            raise ValueError('Cannot downgrade a threshold rule that has a defined cardinality')

        api_contents = api_contents.copy()
        api_contents["threshold"] = api_contents["threshold"].copy()

        # if cardinality was defined with no field or value
        api_contents['threshold'].pop('cardinality', None)
        api_contents["threshold"]["field"] = api_contents["threshold"]["field"][0]

    # finally, downgrade any additional properties that were added
    return strip_additional_properties(version, api_contents)


def downgrade(api_contents: dict, target_version: str):
    """Downgrade a rule to a target stack version."""
    target_semver = Version(target_version)[:2]

    # nothing to do
    if target_semver == Version(definitions.CURRENT_STACK_VERSION)[:2]:
        return api_contents

    # truncate to (major, minor)
    if target_semver not in migrations:
        raise ValueError(f"Unable to downgrade to {target_version}")

    for previous_version, migration_func in reversed(sorted(migrations.items())):
        if previous_version < target_semver:
            break

        api_contents = migration_func(previous_version, api_contents)

    return api_contents
