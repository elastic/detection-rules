# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Identify non-ES|QL rules using ECS fields their related integrations do not declare.

Rules are validated against the union of their related integrations' schemas. Integrations
that declare their ECS fields (per data stream ecs.yml, cached as `_ecs_declared` in
integration-schemas.json.gz) only populate that subset, so any other ECS field in the query
can never match an event from that integration. This module reports those fields.

Rules resolving to at least one integration that inherits the full ECS schema via the
ecs@mappings component template (e.g. cloud_defend, endpoint) are not flagged, since every
ECS field is valid for them. Note that EQL sequence validation additionally checks each
subquery against its own package's schema, which can catch package-scoped violations in
multi-package rules that this union-based scan skips — `validate-all` remains authoritative.

Usage:
    python -m detection_rules dev integrations find-ecs-scope-violations [--output violations.csv]
"""

import csv
import json
import unittest.mock
from pathlib import Path
from typing import Any

import click
from semver import Version

from . import ecs
from .config import load_current_package_version
from .integrations import (
    collect_schema_fields,
    find_latest_compatible_version,
    find_latest_integration_patch_for_minor,
    get_integration_ecs_additions,
    integration_declares_ecs_fields,
    load_integrations_manifests,
    load_integrations_schemas,
)
from .rule import QueryRuleData, TOMLRuleContents
from .rule_loader import RuleCollection
from .schemas import get_stack_schemas

SCANNED_LANGUAGES = ("kuery", "eql")


def load_rules_without_query_validation() -> RuleCollection:
    """Load the default rule collection with query validation disabled."""

    # The scan must be able to load rules whose queries would fail strict ECS scoping,
    # so query validation is bypassed; the queries are still parsed for field extraction.
    def _skip_query_validation(*_args: Any, **_kwargs: Any) -> None:
        return None

    with unittest.mock.patch.object(QueryRuleData, "validate_query", _skip_query_validation):
        return RuleCollection.default()


def scan_rules(package_filter: str | None = None) -> list[dict[str, Any]]:
    """Scan all production KQL/EQL rules for ECS fields their integrations do not declare."""
    packages_manifest = load_integrations_manifests()
    integrations_schemas = load_integrations_schemas()

    current_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
    ecs_version = get_stack_schemas()[str(current_version)]["ecs"]
    flat_ecs_schema = ecs.flatten_multi_fields(ecs.get_schema(ecs_version, name="ecs_flat"))

    violations: list[dict[str, Any]] = []
    rules = load_rules_without_query_validation()

    for rule in rules.rules:
        contents = rule.contents
        if contents.metadata.maturity != "production":
            continue

        data = contents.data
        if not isinstance(data, QueryRuleData) or data.language not in SCANNED_LANGUAGES:
            continue

        validator = data.validator
        if validator is None:
            continue

        package_integrations = TOMLRuleContents.get_packaged_integrations(data, contents.metadata, packages_manifest)
        if not package_integrations:
            continue

        packages = sorted({pk_int["package"] for pk_int in package_integrations})
        if package_filter and package_filter not in packages:
            continue

        patch_floor = find_latest_integration_patch_for_minor(
            set(packages),
            current_version.major,
            current_version.minor,
        )
        min_stack = Version(
            current_version.major,
            current_version.minor,
            max(current_version.patch, patch_floor),
        )

        # union of fields across all listed integrations; if any integration inherits the
        # full ECS schema (ecs@mappings or legacy cache format), the rule cannot violate
        declared_fields: set[str] = set()
        any_full_ecs = False
        for pk_int in package_integrations:
            package = pk_int["package"]
            integration = pk_int["integration"]
            package_schemas = integrations_schemas.get(package, {}) if integration else None
            try:
                package_version, _ = find_latest_compatible_version(
                    package,
                    integration,
                    min_stack,
                    packages_manifest,
                    package_schemas=package_schemas,
                )
            except ValueError:
                any_full_ecs = True  # cannot resolve a schema; do not flag on partial data
                continue

            if not integration_declares_ecs_fields(integrations_schemas, package, package_version, integration):
                any_full_ecs = True
                continue

            declared_fields.update(collect_schema_fields(integrations_schemas, package, package_version, integration))
            declared_fields.update(get_integration_ecs_additions(package, integration))

        if any_full_ecs:
            continue

        unique_fields: list[str] = validator.unique_fields or []
        missing = sorted(f for f in unique_fields if f in flat_ecs_schema and f not in declared_fields)
        if missing:
            violations.append(
                {
                    "rule_path": str(rule.path),
                    "rule_id": data.rule_id,
                    "rule_name": data.name,
                    "packages": packages,
                    "missing_ecs_fields": missing,
                }
            )

    return sorted(violations, key=lambda v: v["rule_path"])


def write_reports(
    violations: list[dict[str, Any]],
    output: Path | None = None,
    json_output: Path | None = None,
) -> None:
    """Write the violations to CSV and/or JSON files."""
    if output:
        with output.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["rule_path", "rule_id", "rule_name", "packages", "missing_ecs_fields"])
            for violation in violations:
                writer.writerow(
                    [
                        violation["rule_path"],
                        violation["rule_id"],
                        violation["rule_name"],
                        ";".join(violation["packages"]),
                        ";".join(violation["missing_ecs_fields"]),
                    ]
                )
        click.echo(f"CSV report written to {output}")

    if json_output:
        _ = json_output.write_text(json.dumps(violations, indent=2) + "\n")
        click.echo(f"JSON report written to {json_output}")


def scan_and_report(
    output: Path | None = None,
    json_output: Path | None = None,
    package_filter: str | None = None,
) -> list[dict[str, Any]]:
    """Run the scan, print a summary, and write any requested reports."""
    violations = scan_rules(package_filter=package_filter)

    for violation in violations:
        fields = ", ".join(violation["missing_ecs_fields"])
        packages = ", ".join(violation["packages"])
        click.echo(f"{violation['rule_path']} [{packages}]: {fields}")
    click.echo(f"{len(violations)} rule(s) with ECS fields not declared by their integrations")

    write_reports(violations, output=output, json_output=json_output)
    return violations
