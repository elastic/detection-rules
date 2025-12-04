# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""CLI commands for detection_rules."""

import dataclasses
import json
import os
import time
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, get_args
from uuid import uuid4

import click
import pytoml  # type: ignore[reportMissingTypeStubs]
from marshmallow_dataclass import class_schema
from semver import Version

from .action_connector import (
    TOMLActionConnectorContents,
    build_action_connector_objects,
    parse_action_connector_results_from_api,
)
from .attack import build_threat_map_entry
from .cli_utils import multi_collection, rule_prompt
from .config import load_current_package_version, parse_rules_config
from .exception import TOMLExceptionContents, build_exception_objects, parse_exceptions_results_from_api
from .generic_loader import GenericCollection
from .misc import (
    add_client,
    getdefault,
    nested_set,
    parse_user_config,
    raise_client_error,
)
from .rule import DeprecatedRule, ESQLRuleData, QueryRuleData, RuleMeta, TOMLRule, TOMLRuleContents
from .rule_formatter import toml_write
from .rule_loader import RawRuleCollection, RuleCollection, update_metadata_from_file
from .rule_validators import ESQLValidator
from .schemas import all_versions, definitions, get_incompatible_fields, get_schema_file
from .utils import (
    Ndjson,
    clear_caches,
    get_etc_path,
    get_path,
    load_dump,  # type: ignore[reportUnknownVariableType]
    load_rule_contents,
    rulename_to_filename,
)

if TYPE_CHECKING:
    from elasticsearch import Elasticsearch

RULES_CONFIG = parse_rules_config()
RULES_DIRS = RULES_CONFIG.rule_dirs


@click.group(
    "detection-rules",
    context_settings={
        "help_option_names": ["-h", "--help"],
        "max_content_width": int(os.getenv("DR_CLI_MAX_WIDTH", 240)),  # noqa: PLW1508
    },
)
@click.option(
    "--debug/--no-debug",
    "-D/-N",
    is_flag=True,
    default=None,
    help="Print full exception stacktrace on errors",
)
@click.pass_context
def root(ctx: click.Context, debug: bool) -> None:
    """Commands for detection-rules repository."""
    debug = debug if debug else parse_user_config().get("debug")
    ctx.obj = {"debug": debug, "rules_config": RULES_CONFIG}
    if debug:
        click.secho("DEBUG MODE ENABLED", fg="yellow")


@root.command("create-rule")
@click.argument("path", type=Path)
@click.option(
    "--config", "-c", type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Rule or config file"
)
@click.option("--required-only", is_flag=True, help="Only prompt for required fields")
@click.option(
    "--rule-type", "-t", type=click.Choice(sorted(TOMLRuleContents.all_rule_types())), help="Type of rule to create"
)
def create_rule(path: Path, config: Path, required_only: bool, rule_type: str):  # noqa: ANN201
    """Create a detection rule."""
    contents: dict[str, Any] = load_rule_contents(config, single_only=True)[0] if config else {}
    return rule_prompt(path, rule_type=rule_type, required_only=required_only, save=True, **contents)


@root.command("generate-rules-index")
@click.option("--query", "-q", help="Optional KQL query to limit to specific rules")
@click.option("--overwrite", is_flag=True, help="Overwrite files in an existing folder")
@click.pass_context
def generate_rules_index(
    ctx: click.Context,
    query: str,
    overwrite: bool,
    save_files: bool = True,
) -> tuple[Ndjson, Ndjson]:
    """Generate enriched indexes of rules, based on a KQL search, for indexing/importing into elasticsearch/kibana."""
    from .packaging import Package

    if query:
        rule_paths = [r["file"] for r in ctx.invoke(search_rules, query=query, verbose=False)]
        rules = RuleCollection()
        rules.load_files(Path(p) for p in rule_paths)
    else:
        rules = RuleCollection.default()

    rule_count = len(rules)
    package = Package(rules, name=load_current_package_version(), verbose=False)
    package_hash = package.get_package_hash()
    bulk_upload_docs, importable_rules_docs = package.create_bulk_index_body()

    if save_files:
        path = get_path(["enriched-rule-indexes", package_hash])
        path.mkdir(parents=True, exist_ok=overwrite)
        bulk_upload_docs.dump(path.joinpath("enriched-rules-index-uploadable.ndjson"), sort_keys=True)
        importable_rules_docs.dump(path.joinpath("enriched-rules-index-importable.ndjson"), sort_keys=True)

        click.echo(f"files saved to: {path}")

    click.echo(f"{rule_count} rules included")

    return bulk_upload_docs, importable_rules_docs


@root.command("import-rules-to-repo")
@click.argument("input-file", type=click.Path(dir_okay=False, exists=True, path_type=Path), nargs=-1, required=False)
@click.option("--action-connector-import", "-ac", is_flag=True, help="Include action connectors in export")
@click.option("--exceptions-import", "-e", is_flag=True, help="Include exceptions in export")
@click.option("--required-only", is_flag=True, help="Only prompt for required fields")
@click.option("--directory", "-d", type=click.Path(file_okay=False, exists=True), help="Load files from a directory")
@click.option(
    "--save-directory",
    "-s",
    type=click.Path(file_okay=False, exists=True, path_type=Path),
    help="Save imported rules to a directory",
)
@click.option(
    "--exceptions-directory",
    "-se",
    type=click.Path(file_okay=False, exists=True, path_type=Path),
    help="Save imported exceptions to a directory",
)
@click.option(
    "--action-connectors-directory",
    "-sa",
    type=click.Path(file_okay=False, exists=True, path_type=Path),
    help="Save imported actions to a directory",
)
@click.option("--skip-errors", "-ske", is_flag=True, help="Skip rule import errors")
@click.option("--default-author", "-da", type=str, required=False, help="Default author for rules missing one")
@click.option("--strip-none-values", "-snv", is_flag=True, help="Strip None values from the rule")
@click.option("--local-creation-date", "-lc", is_flag=True, help="Preserve the local creation date of the rule")
@click.option("--local-updated-date", "-lu", is_flag=True, help="Preserve the local updated date of the rule")
@click.option(
    "--load-rule-loading",
    "-lr",
    is_flag=True,
    help="Enable arbitrary rule loading from the rules directories (Can be very slow!)",
)
def import_rules_into_repo(  # noqa: PLR0912, PLR0913, PLR0915
    input_file: tuple[Path, ...] | None,
    required_only: bool,
    action_connector_import: bool,
    exceptions_import: bool,
    directory: Path | None,
    save_directory: Path,
    action_connectors_directory: Path | None,
    exceptions_directory: Path | None,
    skip_errors: bool,
    default_author: str,
    strip_none_values: bool,
    local_creation_date: bool,
    local_updated_date: bool,
    load_rule_loading: bool,
) -> None:
    """Import rules from json, toml, or yaml files containing Kibana exported rule(s)."""
    errors: list[str] = []

    rule_files: list[Path] = []
    if directory:
        rule_files = list(directory.glob("**/*.*"))

    if input_file:
        rule_files = sorted({*rule_files, *input_file})

    file_contents: list[Any] = []
    for rule_file in rule_files:
        file_contents.extend(load_rule_contents(Path(rule_file)))

    if not file_contents:
        click.echo("Must specify at least one file!")

    raw_rule_collection = RawRuleCollection()
    if load_rule_loading:
        raw_rule_collection = raw_rule_collection.default()

    exceptions_containers = {}
    exceptions_items = {}

    exceptions_containers, exceptions_items, _, unparsed_results = parse_exceptions_results_from_api(file_contents)

    action_connectors, unparsed_results = parse_action_connector_results_from_api(unparsed_results)

    file_contents = unparsed_results

    exception_list_rule_table: dict[str, Any] = {}
    action_connector_rule_table: dict[str, Any] = {}
    rule_count = 0
    for contents in file_contents:
        # Don't load exceptions as rules
        if contents.get("type") not in get_args(definitions.RuleType):
            click.echo(f"Skipping - {contents.get('type')} is not a supported rule type")
            continue
        base_path = contents.get("name") or contents.get("rule", {}).get("name")
        base_path = rulename_to_filename(base_path) if base_path else base_path
        if base_path is None:
            raise ValueError(f"Invalid rule file, please ensure the rule has a name field: {contents}")

        rule_base_path = Path(save_directory or RULES_DIRS[0])
        rule_path = rule_base_path / base_path
        rule_id = contents.get("rule_id")
        if rule_id in raw_rule_collection.id_map:
            rule_path = raw_rule_collection.id_map[rule_id].path or rule_path

        # handle both rule json formats loaded from kibana and toml
        data_view_id = contents.get("data_view_id") or contents.get("rule", {}).get("data_view_id")
        additional = ["index"] if not data_view_id else ["data_view_id"]

        # Use additional to store all available fields for the rule
        additional += [key for key in contents if key not in additional and contents.get(key, None)]

        # use default author if not provided
        contents["author"] = contents.get("author") or default_author or [contents.get("created_by")]
        if isinstance(contents["author"], str):
            contents["author"] = [contents["author"]]

        contents.update(
            update_metadata_from_file(
                rule_path, {"creation_date": local_creation_date, "updated_date": local_updated_date}
            )
        )

        output = rule_prompt(
            rule_path,
            required_only=required_only,
            save=True,
            verbose=True,
            additional_required=additional,
            skip_errors=skip_errors,
            strip_none_values=strip_none_values,
            **contents,
        )
        # If output is not a TOMLRule
        if isinstance(output, str):
            errors.append(output)
        else:
            rule_count += 1

        if contents.get("exceptions_list"):
            # For each item in rule.contents.data.exceptions_list to the exception_list_rule_table under the list_id
            for exception in contents["exceptions_list"]:
                exception_id = exception["list_id"]
                if exception_id not in exception_list_rule_table:
                    exception_list_rule_table[exception_id] = []
                exception_list_rule_table[exception_id].append({"id": contents["id"], "name": contents["name"]})

        if contents.get("actions"):
            # If rule has actions with connectors, add them to the action_connector_rule_table under the action_id
            for action in contents["actions"]:
                action_id = action["id"]
                if action_id not in action_connector_rule_table:
                    action_connector_rule_table[action_id] = []
                action_connector_rule_table[action_id].append({"id": contents["id"], "name": contents["name"]})

    # Build TOMLException Objects
    if exceptions_import:
        _, e_output, e_errors = build_exception_objects(
            exceptions_containers,
            exceptions_items,
            exception_list_rule_table,
            exceptions_directory,
            save_toml=True,
            skip_errors=skip_errors,
            verbose=True,
        )
        for line in e_output:
            click.echo(line)
        errors.extend(e_errors)

    # Build TOMLActionConnector Objects
    if action_connector_import:
        _, ac_output, ac_errors = build_action_connector_objects(
            action_connectors,
            action_connector_rule_table,
            action_connectors_directory,
            save_toml=True,
            skip_errors=skip_errors,
            verbose=True,
        )
        for line in ac_output:
            click.echo(line)
        errors.extend(ac_errors)

    exceptions_count = 0 if not exceptions_import else len(exceptions_containers) + len(exceptions_items)
    click.echo(f"{rule_count + exceptions_count + len(action_connectors)} results exported")
    click.echo(f"{rule_count} rules converted")
    click.echo(f"{exceptions_count} exceptions exported")
    click.echo(f"{len(action_connectors)} actions connectors exported")
    if errors:
        _dir = save_directory if save_directory else RULES_DIRS[0]
        err_file = _dir / "_errors.txt"
        _ = err_file.write_text("\n".join(errors))
        click.echo(f"{len(errors)} errors saved to {err_file}")


@root.command("build-limited-rules")
@click.option(
    "--stack-version",
    type=click.Choice(all_versions()),
    required=True,
    help="Version to downgrade to be compatible with the older instance of Kibana",
)
@click.option("--output-file", "-o", type=click.Path(dir_okay=False, exists=False), required=True)
def build_limited_rules(stack_version: str, output_file: str) -> None:
    """
    Import rules from json, toml, or Kibana exported rule file(s),
    filter out unsupported ones, and write to output NDJSON file.
    """

    # Schema generation and incompatible fields detection
    query_rule_data = class_schema(QueryRuleData)()
    fields = getattr(query_rule_data, "fields", {})
    incompatible_fields = get_incompatible_fields(
        list(fields.values()), Version.parse(stack_version, optional_minor_and_patch=True)
    )

    # Load all rules
    rules = RuleCollection.default()

    # Define output path
    output_path = Path(output_file)

    # Define ndjson instance for output
    ndjson_output = Ndjson()

    # Get API schema for rule type
    api_schema = get_schema_file(stack_version, "base")["properties"]["type"]["enum"]

    # Function to process each rule
    def process_rule(rule: TOMLRule, incompatible_fields: list[str]) -> dict[str, Any] | None:
        if rule.contents.type not in api_schema:
            click.secho(
                f"{rule.contents.name} - Skipping unsupported rule type: {rule.contents.get('type')}", fg="yellow"
            )
            return None

        # Remove unsupported fields from rule
        rule_contents = rule.contents.to_api_format()
        for field in incompatible_fields:
            rule_contents.pop(field, None)

        return rule_contents

    # Process each rule and add to ndjson_output
    for rule in rules.rules:
        processed_rule = process_rule(rule, incompatible_fields)
        if processed_rule is not None:
            ndjson_output.append(processed_rule)

    # Write ndjson_output to file
    ndjson_output.dump(output_path)

    click.echo(f"Success: Rules written to {output_file}")


@root.command("toml-lint")
@click.option(
    "--rule-file",
    "-f",
    multiple=True,
    type=click.Path(exists=True, path_type=Path),
    help="Specify one or more rule files.",
)
def toml_lint(rule_file: list[Path]) -> None:
    """Cleanup files with some simple toml formatting."""
    if rule_file:
        rules = RuleCollection()
        rules.load_files(Path(p) for p in rule_file)
    else:
        rules = RuleCollection.default()

    # re-save the rules to force TOML reformatting
    for rule in rules:
        rule.save_toml()

    click.echo("TOML file linting complete")


@root.command("mass-update")
@click.argument("query")
@click.option("--metadata", "-m", is_flag=True, help="Make an update to the rule metadata rather than contents.")
@click.option("--language", type=click.Choice(["eql", "kql"]), default="kql")
@click.option(
    "--field",
    type=(str, str),
    multiple=True,
    help="Use rule-search to retrieve a subset of rules and modify values "
    "(ex: --field management.ecs_version 1.1.1).\n"
    "Note this is limited to string fields only. Nested fields should use dot notation.",
)
@click.pass_context
def mass_update(
    ctx: click.Context,
    query: str,
    metadata: bool,
    language: Literal["eql", "kql"],
    field: tuple[str, str],
) -> Any:
    """Update multiple rules based on eql results."""
    rules = RuleCollection().default()
    results = ctx.invoke(search_rules, query=query, language=language, verbose=False)
    matching_ids = {r["rule_id"] for r in results}
    rules = rules.filter(lambda r: r.id in matching_ids)

    for rule in rules:
        for key, value in field:
            nested_set(rule.metadata if metadata else rule.contents, key, value)  # type: ignore[reportAttributeAccessIssue]

        rule.validate(as_rule=True)  # type: ignore[reportAttributeAccessIssue]
        rule.save(as_rule=True)  # type: ignore[reportAttributeAccessIssue]

    return ctx.invoke(
        search_rules,
        query=query,
        language=language,
        columns=["rule_id", "name"] + [k[0].split(".")[-1] for k in field],
    )


@root.command("view-rule")
@click.argument("rule-file", type=Path)
@click.option("--api-format/--rule-format", default=True, help="Print the rule in final api or rule format")
@click.option("--esql-remote-validation", is_flag=True, default=False, help="Enable remote validation for the rule")
@click.pass_context
def view_rule(
    _: click.Context, rule_file: Path, api_format: str, esql_remote_validation: bool
) -> TOMLRule | DeprecatedRule:
    """View an internal rule or specified rule file."""
    rule = RuleCollection().load_file(rule_file)
    if (
        esql_remote_validation
        and isinstance(rule.contents.data, ESQLRuleData)
        and isinstance(rule.contents.data.validator, ESQLValidator)
        and isinstance(rule.contents.metadata, RuleMeta)
        and not getdefault("remote_esql_validation")()
    ):
        rule.contents.data.validator.validate(rule.contents.data, rule.contents.metadata, force_remote_validation=True)

    if api_format:
        click.echo(json.dumps(rule.contents.to_api_format(), indent=2, sort_keys=True))
    else:
        click.echo(toml_write(rule.contents.to_dict()))  # type: ignore[reportAttributeAccessIssue]

    return rule


def _export_rules(  # noqa: PLR0913
    rules: RuleCollection,
    outfile: Path,
    downgrade_version: definitions.SemVer | None = None,
    verbose: bool = True,
    skip_unsupported: bool = False,
    include_metadata: bool = False,
    include_action_connectors: bool = False,
    include_exceptions: bool = False,
) -> None:
    """Export rules and exceptions into a consolidated ndjson file."""
    from .rule import downgrade_contents_from_rule

    outfile = outfile.with_suffix(".ndjson")
    unsupported: list[str] = []

    output_lines: list[str] = []
    if downgrade_version:
        for rule in rules:
            try:
                output_lines.append(
                    json.dumps(
                        downgrade_contents_from_rule(rule, downgrade_version, include_metadata=include_metadata),
                        sort_keys=True,
                    )
                )
            except ValueError as e:
                if skip_unsupported:
                    unsupported.append(f"{e}: {rule.id} - {rule.name}")
                else:
                    raise
    else:
        output_lines = [
            json.dumps(r.contents.to_api_format(include_metadata=include_metadata), sort_keys=True) for r in rules
        ]

    # Add exceptions to api format here and add to output_lines
    if include_exceptions or include_action_connectors:
        cl = GenericCollection.default()
        # Get exceptions in API format
        if include_exceptions:
            exceptions = [d.contents.to_api_format() for d in cl.items if isinstance(d.contents, TOMLExceptionContents)]
            exceptions = [e for sublist in exceptions for e in sublist]
            output_lines.extend(json.dumps(e, sort_keys=True) for e in exceptions)
        if include_action_connectors:
            action_connectors = [
                d.contents.to_api_format() for d in cl.items if isinstance(d.contents, TOMLActionConnectorContents)
            ]
            actions = [a for sublist in action_connectors for a in sublist]
            output_lines.extend(json.dumps(a, sort_keys=True) for a in actions)

    _ = outfile.write_text("\n".join(output_lines) + "\n")

    if verbose:
        click.echo(f"Exported {len(rules) - len(unsupported)} rules into {outfile}")

        if skip_unsupported and unsupported:
            unsupported_str = "\n- ".join(unsupported)
            click.echo(f"Skipped {len(unsupported)} unsupported rules: \n- {unsupported_str}")


@root.command("export-rules-from-repo")
@multi_collection
@click.option(
    "--outfile",
    "-o",
    default=Path(get_path(["exports", f"{time.strftime('%Y%m%dT%H%M%SL')}.ndjson"])),
    type=Path,
    help="Name of file for exported rules",
)
@click.option("--replace-id", "-r", is_flag=True, help="Replace rule IDs with new IDs before export")
@click.option(
    "--stack-version",
    type=click.Choice(all_versions()),
    help="Downgrade a rule version to be compatible with older instances of Kibana",
)
@click.option(
    "--skip-unsupported",
    "-s",
    is_flag=True,
    help="If `--stack-version` is passed, skip rule types which are unsupported (an error will be raised otherwise)",
)
@click.option("--include-metadata", type=bool, is_flag=True, default=False, help="Add metadata to the exported rules")
@click.option(
    "--include-action-connectors",
    "-ac",
    type=bool,
    is_flag=True,
    default=False,
    help="Include Action Connectors in export",
)
@click.option(
    "--include-exceptions", "-e", type=bool, is_flag=True, default=False, help="Include Exceptions Lists in export"
)
def export_rules_from_repo(  # noqa: PLR0913
    rules: RuleCollection,
    outfile: Path,
    replace_id: bool,
    stack_version: str,
    skip_unsupported: bool,
    include_metadata: bool,
    include_action_connectors: bool,
    include_exceptions: bool,
) -> RuleCollection:
    """Export rule(s) and exception(s) into an importable ndjson file."""
    if len(rules) == 0:
        raise ValueError("No rules found")

    if replace_id:
        # if we need to replace the id, take each rule object and create a copy
        # of it, with only the rule_id field changed
        old_rules = rules
        rules = RuleCollection()

        for rule in old_rules:
            new_data = dataclasses.replace(rule.contents.data, rule_id=str(uuid4()))
            new_contents = dataclasses.replace(rule.contents, data=new_data)
            rules.add_rule(TOMLRule(contents=new_contents))

    outfile.parent.mkdir(exist_ok=True)
    _export_rules(
        rules=rules,
        outfile=outfile,
        downgrade_version=stack_version,
        skip_unsupported=skip_unsupported,
        include_metadata=include_metadata,
        include_action_connectors=include_action_connectors,
        include_exceptions=include_exceptions,
    )

    return rules


@root.command("validate-rule")
@click.argument("path")
@click.pass_context
def validate_rule(_: click.Context, path: str) -> TOMLRule | DeprecatedRule:
    """Check if a rule staged in rules dir validates against a schema."""
    rule = RuleCollection().load_file(Path(path))
    click.echo("Rule validation successful")
    return rule


@root.command("validate-all")
def validate_all() -> None:
    """Check if all rules validates against a schema."""
    _ = RuleCollection.default()
    click.echo("Rule validation successful")


@root.command("rule-search")
@click.argument("query", required=False)
@click.option("--columns", "-c", multiple=True, help="Specify columns to add the table")
@click.option("--language", type=click.Choice(["eql", "kql"]), default="kql")
@click.option("--count", is_flag=True, help="Return a count rather than table")
def search_rules(  # noqa: PLR0913
    query: str | None,
    columns: list[str],
    language: Literal["eql", "kql"],
    count: bool,
    verbose: bool = True,
    rules: dict[str, TOMLRule] | None = None,
    pager: bool = False,
) -> list[dict[str, Any]]:
    """Use KQL or EQL to find matching rules."""
    from eql import parse_query  # type: ignore[reportMissingTypeStubs]
    from eql.build import get_engine  # type: ignore[reportMissingTypeStubs]
    from eql.pipes import CountPipe  # type: ignore[reportMissingTypeStubs]
    from eql.table import Table  # type: ignore[reportMissingTypeStubs]
    from kql import get_evaluator  # type: ignore[reportMissingTypeStubs]

    from .rule import get_unique_query_fields

    flattened_rules: list[dict[str, Any]] = []
    rules = rules or {str(rule.path): rule for rule in RuleCollection.default()}

    for file_name, rule in rules.items():
        flat: dict[str, Any] = {"file": os.path.relpath(file_name)}
        flat.update(rule.contents.to_dict())
        flat.update(flat["metadata"])
        flat.update(flat["rule"])

        tactic_names: list[str] = []
        technique_ids: list[str] = []
        subtechnique_ids: list[str] = []

        for entry in flat["rule"].get("threat", []):
            if entry["framework"] != "MITRE ATT&CK":
                continue

            techniques = entry.get("technique", [])
            tactic_names.append(entry["tactic"]["name"])
            technique_ids.extend([t["id"] for t in techniques])
            subtechnique_ids.extend([st["id"] for t in techniques for st in t.get("subtechnique", [])])

        flat.update(
            techniques=technique_ids,
            tactics=tactic_names,
            subtechniques=subtechnique_ids,
            unique_fields=get_unique_query_fields(rule),
        )
        flattened_rules.append(flat)

    flattened_rules.sort(key=lambda dct: dct["name"])

    filtered: list[dict[str, Any]] = []
    if language == "kql":
        evaluator = get_evaluator(query) if query else lambda _: True  # type: ignore[reportUnknownLambdaType]
        filtered = list(filter(evaluator, flattened_rules))  # type: ignore[reportCallIssue]
    elif language == "eql":
        parsed = parse_query(query, implied_any=True, implied_base=True)  # type: ignore[reportUnknownVariableType]
        evaluator = get_engine(parsed)  # type: ignore[reportUnknownVariableType]
        filtered = [result.events[0].data for result in evaluator(flattened_rules)]  # type: ignore[reportUnknownVariableType]

        if not columns and any(isinstance(pipe, CountPipe) for pipe in parsed.pipes):  # type: ignore[reportAttributeAccessIssue]
            columns = ["key", "count", "percent"]

    if count:
        click.echo(f"{len(filtered)} rules")
        return filtered

    columns = ",".join(columns).split(",") if columns else ["rule_id", "file", "name"]

    table: Table = Table.from_list(columns, filtered)  # type: ignore[reportUnknownMemberType]

    if verbose:
        click.echo_via_pager(table) if pager else click.echo(table)

    return filtered


@root.command("build-threat-map-entry")
@click.argument("tactic")
@click.argument("technique-ids", nargs=-1)
def build_threat_map(tactic: str, technique_ids: Iterable[str]) -> dict[str, Any]:
    """Build a threat map entry."""
    entry = build_threat_map_entry(tactic, *technique_ids)
    rendered = pytoml.dumps({"rule": {"threat": [entry]}})  # type: ignore[reportUnknownMemberType]
    # strip out [rule]
    cleaned = "\n".join(rendered.splitlines()[2:])
    print(cleaned)
    return entry


@root.command("test")
@click.pass_context
def test_rules(ctx: click.Context) -> None:
    """Run unit tests over all of the rules."""
    import pytest

    rules_config = ctx.obj["rules_config"]
    test_config = rules_config.test_config
    tests, skipped = test_config.get_test_names(formatted=True)

    if skipped:
        click.echo(f"Tests skipped per config ({len(skipped)}):")
        click.echo("\n".join(skipped))

    clear_caches()
    if tests:
        ctx.exit(pytest.main(["-v", *tests]))
    else:
        click.echo("No tests found to execute!")


@root.group("typosquat")
def typosquat_group() -> None:
    """Commands for generating typosquat detections."""


@typosquat_group.command("create-dnstwist-index")
@click.argument("input-file", type=click.Path(exists=True, dir_okay=False), required=True)
@click.pass_context
@add_client(["elasticsearch"], add_func_arg=False)
def create_dnstwist_index(ctx: click.Context, input_file: click.Path) -> None:
    """Create a dnstwist index in Elasticsearch to work with a threat match rule."""
    es_client: Elasticsearch = ctx.obj["es"]

    click.echo(f"Attempting to load dnstwist data from {input_file}")
    dnstwist_data: list[dict[str, Any]] = load_dump(str(input_file))  # type: ignore[reportAssignmentType]
    click.echo(f"{len(dnstwist_data)} records loaded")

    original_domain = next(r["domain-name"] for r in dnstwist_data if r.get("fuzzer", "") == "original*")  # type: ignore[reportAttributeAccessIssue]
    click.echo(f"Original domain name identified: {original_domain}")

    domain = original_domain.split(".")[0]
    domain_index = f"dnstwist-{domain}"
    # If index already exists, prompt user to confirm if they want to overwrite
    if es_client.indices.exists(index=domain_index) and click.confirm(
        f"dnstwist index: {domain_index} already exists for {original_domain}. Do you want to overwrite?",
        abort=True,
    ):
        _ = es_client.indices.delete(index=domain_index)

    fields = [
        "dns-a",
        "dns-aaaa",
        "dns-mx",
        "dns-ns",
        "banner-http",
        "fuzzer",
        "original-domain",
        "dns.question.registered_domain",
    ]
    timestamp_field = "@timestamp"
    mappings = {"mappings": {"properties": {f: {"type": "keyword"} for f in fields}}}
    mappings["mappings"]["properties"][timestamp_field] = {"type": "date"}

    _ = es_client.indices.create(index=domain_index, body=mappings)

    # handle dns.question.registered_domain separately
    _ = fields.pop()
    es_updates: list[dict[str, Any]] = []
    now = datetime.now(UTC)

    for item in dnstwist_data:
        if item["fuzzer"] == "original*":
            continue

        record = item.copy()
        record.setdefault("dns", {}).setdefault("question", {}).setdefault("registered_domain", item.get("domain-name"))

        for field in fields:
            _ = record.setdefault(field, None)

        record["@timestamp"] = now

        es_updates.extend([{"create": {"_index": domain_index}}, record])

    click.echo(f"Indexing data for domain {original_domain}")

    results = es_client.bulk(body=es_updates)
    if results["errors"]:
        error = {r["create"]["result"] for r in results["items"] if r["create"]["status"] != 201}  # noqa: PLR2004
        raise_client_error(f"Errors occurred during indexing:\n{error}")

    click.echo(f"{len(results['items'])} watchlist domains added to index")
    click.echo("Run `prep-rule` and import to Kibana to create alerts on this index")


@typosquat_group.command("prep-rule")
@click.argument("author")
def prep_rule(author: str) -> None:
    """Prep the detection threat match rule for dnstwist data with a rule_id and author."""
    rule_template_file = get_etc_path(["rule_template_typosquatting_domain.json"])
    template_rule = json.loads(rule_template_file.read_text())
    template_rule.update(author=[author], rule_id=str(uuid4()))
    updated_rule = get_path(["rule_typosquatting_domain.ndjson"])
    _ = updated_rule.write_text(json.dumps(template_rule, sort_keys=True))
    click.echo(f"Rule saved to: {updated_rule}. Import this to Kibana to create alerts on all dnstwist-* indexes")
    click.echo("Note: you only need to import and enable this rule one time for all dnstwist-* indexes")
