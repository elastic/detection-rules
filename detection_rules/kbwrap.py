# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Kibana cli commands."""

import re
import sys
from pathlib import Path
from typing import Any, cast

import click
import kql  # type: ignore[reportMissingTypeStubs]
from kibana import RuleResource, Signal  # type: ignore[reportMissingTypeStubs]

from .action_connector import (
    TOMLActionConnector,
    TOMLActionConnectorContents,
    build_action_connector_objects,
    parse_action_connector_results_from_api,
)
from .cli_utils import multi_collection
from .config import parse_rules_config
from .exception import TOMLException, TOMLExceptionContents, build_exception_objects, parse_exceptions_results_from_api
from .generic_loader import GenericCollection, GenericCollectionTypes
from .main import root
from .misc import add_params, get_kibana_client, kibana_options, nested_set, raise_client_error
from .rule import TOMLRule, TOMLRuleContents, downgrade_contents_from_rule
from .rule_loader import RawRuleCollection, RuleCollection, update_metadata_from_file
from .schemas import definitions  # noqa: TC001
from .utils import CUSTOM_RULES_KQL, format_command_options, rulename_to_filename

RULES_CONFIG = parse_rules_config()


@root.group("kibana")
@add_params(*kibana_options)
@click.pass_context
def kibana_group(ctx: click.Context, **kibana_kwargs: Any) -> None:
    """Commands for integrating with Kibana."""
    _ = ctx.ensure_object(dict)  # type: ignore[reportUnknownVariableType]

    # only initialize an kibana client if the subcommand is invoked without help (hacky)
    if sys.argv[-1] in ctx.help_option_names:
        click.echo("Kibana client:")
        click.echo(format_command_options(ctx))

    else:
        ctx.obj["kibana"] = get_kibana_client(**kibana_kwargs)


@kibana_group.command("upload-rule")
@multi_collection
@click.option("--replace-id", "-r", is_flag=True, help="Replace rule IDs with new IDs before export")
@click.pass_context
def upload_rule(ctx: click.Context, rules: RuleCollection, replace_id: bool) -> list[RuleResource]:
    """[Deprecated] Upload a list of rule .toml files to Kibana."""
    kibana = ctx.obj["kibana"]
    api_payloads: list[RuleResource] = []

    click.secho(
        "WARNING: This command is deprecated as of Elastic Stack version 9.0. Please use `kibana import-rules`.",
        fg="yellow",
    )

    for rule in rules:
        try:
            payload = downgrade_contents_from_rule(rule, kibana.version, replace_id=replace_id)
        except ValueError as e:
            raise_client_error(f"{e} in version:{kibana.version}, for rule: {rule.name}", e, ctx=ctx)

        api_payloads.append(RuleResource(payload))

    with kibana:
        results: list[RuleResource] = RuleResource.bulk_create_legacy(api_payloads)  # type: ignore[reportUnknownMemberType]

    success: list[str] = []
    errors: list[str] = []
    for result in results:
        if "error" in result:
            errors.append(f"{result['rule_id']} - {result['error']['message']}")
        else:
            success.append(result["rule_id"])  # type: ignore[reportUnknownArgumentType]

    if success:
        click.echo("Successful uploads:\n  - " + "\n  - ".join(success))
    if errors:
        click.echo("Failed uploads:\n  - " + "\n  - ".join(errors))

    return results


@kibana_group.command("import-rules")
@multi_collection
@click.option("--overwrite", "-o", is_flag=True, help="Overwrite existing rules")
@click.option("--overwrite-exceptions", "-e", is_flag=True, help="Overwrite exceptions in existing rules")
@click.option(
    "--overwrite-action-connectors",
    "-ac",
    is_flag=True,
    help="Overwrite action connectors in existing rules",
)
@click.pass_context
def kibana_import_rules(  # noqa: PLR0915
    ctx: click.Context,
    rules: RuleCollection,
    overwrite: bool = False,
    overwrite_exceptions: bool = False,
    overwrite_action_connectors: bool = False,
) -> tuple[dict[str, Any], list[RuleResource]]:
    """Import custom rules into Kibana."""

    def _handle_response_errors(response: dict[str, Any]) -> None:
        """Handle errors from the import response."""

        def _parse_list_id(s: str) -> str | None:
            """Parse the list ID from the error message."""
            match = re.search(r'list_id: "(.*?)"', s)
            return match.group(1) if match else None

        # Re-try to address known Kibana issue: https://github.com/elastic/kibana/issues/143864
        workaround_errors: list[str] = []
        workaround_error_types: set[str] = set()

        flattened_exceptions = [e for sublist in exception_dicts for e in sublist]
        all_exception_list_ids = {exception["list_id"] for exception in flattened_exceptions}

        click.echo(f"{len(response['errors'])} rule(s) failed to import!")

        action_connector_validation_error = "Error validating create data"
        action_connector_type_error = "expected value of type [string] but got [undefined]"
        for error in response["errors"]:
            error_message = error["error"]["message"]
            click.echo(f" - {error['rule_id']}: ({error['error']['status_code']}) {error_message}")

            if "references a non existent exception list" in error_message:
                list_id = _parse_list_id(error_message)
                if list_id in all_exception_list_ids:
                    workaround_errors.append(error["rule_id"])
                    workaround_error_types.add("non existent exception list")

            if action_connector_validation_error in error_message and action_connector_type_error in error_message:
                workaround_error_types.add("connector still being built")

        if workaround_errors:
            workaround_errors = list(set(workaround_errors))
            if "non existent exception list" in workaround_error_types:
                click.echo(
                    f"Missing exception list errors detected for {len(workaround_errors)} rules. "
                    "Try re-importing using the following command and rule IDs:\n"
                )
                click.echo("python -m detection_rules kibana import-rules -o ", nl=False)
                click.echo(" ".join(f"-id {rule_id}" for rule_id in workaround_errors))
                click.echo()
            if "connector still being built" in workaround_error_types:
                click.echo(
                    f"Connector still being built errors detected for {len(workaround_errors)} rules. "
                    "Please try re-importing the rules again."
                )
                click.echo()

    def _matches_rule_ids(item: GenericCollectionTypes, rule_ids: set[str]) -> bool:
        """Check if the item matches any of the rule IDs in the provided set."""
        return any(rule_id in rule_ids for rule_id in item.contents.metadata.get("rule_ids", []))

    def _process_imported_items(
        imported_items_list: list[list[dict[str, Any]]],
        item_type_description: str,
        item_key: str,
    ) -> None:
        """Displays appropriately formatted success message that all items imported successfully."""
        all_ids = {item[item_key] for sublist in imported_items_list for item in sublist}
        if all_ids:
            click.echo(f"{len(all_ids)} {item_type_description} successfully imported")
            ids_str = "\n - ".join(all_ids)
            click.echo(f" - {ids_str}")

    kibana = ctx.obj["kibana"]
    rule_dicts = [r.contents.to_api_format() for r in rules]
    rule_ids = {rule["rule_id"] for rule in rule_dicts}
    with kibana:
        cl = GenericCollection.default()
        exception_dicts = [
            d.contents.to_api_format()
            for d in cl.items
            if isinstance(d.contents, TOMLExceptionContents) and _matches_rule_ids(d, rule_ids)
        ]
        action_connectors_dicts = [
            d.contents.to_api_format()
            for d in cl.items
            if isinstance(d.contents, TOMLActionConnectorContents) and _matches_rule_ids(d, rule_ids)
        ]
        response, successful_rule_ids, results = RuleResource.import_rules(  # type: ignore[reportUnknownMemberType]
            rule_dicts,
            exception_dicts,
            action_connectors_dicts,
            overwrite=overwrite,
            overwrite_exceptions=overwrite_exceptions,
            overwrite_action_connectors=overwrite_action_connectors,
        )

    if successful_rule_ids:
        click.echo(f"{len(successful_rule_ids)} rule(s) successfully imported")  # type: ignore[reportUnknownArgumentType]
        rule_str = "\n - ".join(successful_rule_ids)  # type: ignore[reportUnknownArgumentType]
        click.echo(f" - {rule_str}")
    if response["errors"]:
        _handle_response_errors(response)  # type: ignore[reportUnknownArgumentType]
    else:
        _process_imported_items(exception_dicts, "exception list(s)", "list_id")
        _process_imported_items(action_connectors_dicts, "action connector(s)", "id")

    return response, results  # type: ignore[reportUnknownVariableType]


@kibana_group.command("export-rules")
@click.option("--directory", "-d", required=True, type=Path, help="Directory to export rules to")
@click.option(
    "--action-connectors-directory", "-acd", required=False, type=Path, help="Directory to export action connectors to"
)
@click.option("--exceptions-directory", "-ed", required=False, type=Path, help="Directory to export exceptions to")
@click.option("--default-author", "-da", type=str, required=False, help="Default author for rules missing one")
@click.option("--rule-id", "-r", multiple=True, help="Optional Rule IDs to restrict export to")
@click.option(
    "--rule-name",
    "-rn",
    required=False,
    help="Optional Rule name to restrict export to (KQL, case-insensitive, supports wildcards)",
)
@click.option("--export-action-connectors", "-ac", is_flag=True, help="Include action connectors in export")
@click.option("--export-exceptions", "-e", is_flag=True, help="Include exceptions in export")
@click.option("--skip-errors", "-s", is_flag=True, help="Skip errors when exporting rules")
@click.option("--strip-version", "-sv", is_flag=True, help="Strip the version fields from all rules")
@click.option(
    "--no-tactic-filename",
    "-nt",
    is_flag=True,
    help="Exclude tactic prefix in exported filenames for rules. "
    "Use same flag for import-rules to prevent warnings and disable its unit test.",
)
@click.option("--local-creation-date", "-lc", is_flag=True, help="Preserve the local creation date of the rule")
@click.option("--local-updated-date", "-lu", is_flag=True, help="Preserve the local updated date of the rule")
@click.option("--custom-rules-only", "-cro", is_flag=True, help="Only export custom rules")
@click.option(
    "--export-query",
    "-eq",
    type=str,
    required=False,
    help=(
        "Apply a query filter to exporting rules e.g. "
        '"alert.attributes.tags: \\"test\\"" to filter for rules that have the tag "test"'
    ),
)
@click.option(
    "--load-rule-loading",
    "-lr",
    is_flag=True,
    help="Enable arbitrary rule loading from the rules directories (Can be very slow!)",
)
@click.pass_context
def kibana_export_rules(  # noqa: PLR0912, PLR0913, PLR0915
    ctx: click.Context,
    directory: Path,
    action_connectors_directory: Path | None,
    exceptions_directory: Path | None,
    default_author: str,
    rule_id: list[str] | None = None,
    rule_name: str | None = None,
    export_action_connectors: bool = False,
    export_exceptions: bool = False,
    skip_errors: bool = False,
    strip_version: bool = False,
    no_tactic_filename: bool = False,
    local_creation_date: bool = False,
    local_updated_date: bool = False,
    custom_rules_only: bool = False,
    export_query: str | None = None,
    load_rule_loading: bool = False,
) -> list[TOMLRule]:
    """Export custom rules from Kibana."""
    kibana = ctx.obj["kibana"]
    kibana_include_details = export_exceptions or export_action_connectors or custom_rules_only or export_query

    # Only allow one of rule_id or rule_name
    if rule_name and rule_id:
        raise click.UsageError("Cannot use --rule-id and --rule-name together. Please choose one.")

    raw_rule_collection = RawRuleCollection()
    if load_rule_loading:
        raw_rule_collection = raw_rule_collection.default()

    with kibana:
        # Look up rule IDs by name if --rule-name was provided
        if rule_name:
            found = RuleResource.find(filter=f"alert.attributes.name:{rule_name}")  # type: ignore[reportUnknownMemberType]
            rule_id = [r["rule_id"] for r in found]  # type: ignore[reportUnknownVariableType]
            if not rule_id:
                click.echo(
                    f"No rules found to export matching the provided name '{rule_name}' "
                    f"using filter 'alert.attributes.name:{rule_name}'"
                )
                return []
        query = (
            export_query
            if not custom_rules_only
            else (f"({CUSTOM_RULES_KQL}){f' and ({export_query})' if export_query else ''}")
        )

        results = (  # type: ignore[reportUnknownVariableType]
            RuleResource.bulk_export(rule_ids=list(rule_id), query=query)  # type: ignore[reportArgumentType]
            if query
            else RuleResource.export_rules(list(rule_id), exclude_export_details=not kibana_include_details)  # type: ignore[reportArgumentType]
        )
    # Handle Exceptions Directory Location
    if results and exceptions_directory:
        exceptions_directory.mkdir(parents=True, exist_ok=True)
    exceptions_directory = exceptions_directory or RULES_CONFIG.exception_dir
    if not exceptions_directory and export_exceptions:
        click.echo("Warning: Exceptions export requested, but no exceptions directory found")

    # Handle Actions Connector Directory Location
    if results and action_connectors_directory:
        action_connectors_directory.mkdir(parents=True, exist_ok=True)
    action_connectors_directory = action_connectors_directory or RULES_CONFIG.action_connector_dir
    if not action_connectors_directory and export_action_connectors:
        click.echo("Warning: Action Connector export requested, but no Action Connector directory found")

    if results:
        directory.mkdir(parents=True, exist_ok=True)
    else:
        click.echo("No rules found to export")
        return []

    rules_results = results  # type: ignore[reportUnknownVariableType]
    action_connector_results = []
    exception_results = []
    results_len = len(results)  # type: ignore[reportUnknownVariableType]
    if kibana_include_details:
        # Assign counts to variables
        results_len = results_len - 1
        rules_count = results[-1]["exported_rules_count"]  # type: ignore[reportUnknownVariableType]
        exception_list_count = results[-1]["exported_exception_list_count"]  # type: ignore[reportUnknownVariableType]
        exception_list_item_count = results[-1]["exported_exception_list_item_count"]  # type: ignore[reportUnknownVariableType]
        action_connector_count = results[-1]["exported_action_connector_count"]  # type: ignore[reportUnknownVariableType]

        # Parse rules results and exception results from API return
        rules_results = results[:rules_count]  # type: ignore[reportUnknownVariableType]
        exception_results = results[rules_count : rules_count + exception_list_count + exception_list_item_count]  # type: ignore[reportUnknownVariableType]
        rules_and_exceptions_count = rules_count + exception_list_count + exception_list_item_count  # type: ignore[reportUnknownVariableType]
        action_connector_results = results[  # type: ignore[reportUnknownVariableType]
            rules_and_exceptions_count : rules_and_exceptions_count + action_connector_count
        ]

    errors: list[str] = []
    exported: list[TOMLRule] = []
    exception_list_rule_table: dict[str, list[dict[str, Any]]] = {}
    action_connector_rule_table: dict[str, list[dict[str, Any]]] = {}
    for rule_resource in rules_results:  # type: ignore[reportUnknownVariableType]
        try:
            if strip_version:
                rule_resource.pop("revision", None)  # type: ignore[reportUnknownMemberType]
                rule_resource.pop("version", None)  # type: ignore[reportUnknownMemberType]
            rule_resource["author"] = rule_resource.get("author") or default_author or [rule_resource.get("created_by")]  # type: ignore[reportUnknownMemberType]
            if isinstance(rule_resource["author"], str):
                rule_resource["author"] = [rule_resource["author"]]
            # Inherit maturity and optionally local dates from the rule if it already exists
            params: dict[str, Any] = {
                "rule": rule_resource,
                "maturity": "development",
            }
            threat = rule_resource.get("threat")  # type: ignore[reportUnknownMemberType]
            first_tactic = threat[0].get("tactic").get("name") if threat else ""  # type: ignore[reportUnknownMemberType]
            # Check if flag or config is set to not include tactic in the filename
            no_tactic_filename = no_tactic_filename or RULES_CONFIG.no_tactic_filename
            # Check if the flag is set to not include tactic in the filename
            tactic_name = first_tactic if not no_tactic_filename else None  # type: ignore[reportUnknownMemberType]
            rule_name = rulename_to_filename(rule_resource.get("name"), tactic_name=tactic_name)  # type: ignore[reportUnknownMemberType]

            save_path = directory / f"{rule_name}"

            # Get local rule data if load_rule_loading is enabled. If not enabled rules variable will be None.
            local_rule: dict[str, Any] = params.get("rule", {})
            input_rule_id: str | None = None

            if local_rule:
                input_rule_id = cast("definitions.UUIDString", local_rule.get("rule_id"))

            if input_rule_id and input_rule_id in raw_rule_collection.id_map:
                save_path = raw_rule_collection.id_map[input_rule_id].path or save_path
            params.update(
                update_metadata_from_file(
                    save_path, {"creation_date": local_creation_date, "updated_date": local_updated_date}
                )
            )
            contents = TOMLRuleContents.from_rule_resource(**params)  # type: ignore[reportArgumentType]
            rule = TOMLRule(contents=contents, path=save_path)
        except Exception as e:
            if skip_errors:
                print(f"- skipping {rule_resource.get('name')} - {type(e).__name__}")  # type: ignore[reportUnknownMemberType]
                errors.append(f"- {rule_resource.get('name')} - {e}")  # type: ignore[reportUnknownMemberType]
                continue
            raise
        if rule.contents.data.exceptions_list:
            # For each item in rule.contents.data.exceptions_list to the exception_list_rule_table under the list_id
            for exception in rule.contents.data.exceptions_list:
                exception_id = exception["list_id"]
                if exception_id not in exception_list_rule_table:
                    exception_list_rule_table[exception_id] = []
                exception_list_rule_table[exception_id].append({"id": rule.id, "name": rule.name})
        if rule.contents.data.actions:
            # use connector ids as rule source
            for action in rule.contents.data.actions:
                action_id = action["id"]
                if action_id not in action_connector_rule_table:
                    action_connector_rule_table[action_id] = []
                action_connector_rule_table[action_id].append({"id": rule.id, "name": rule.name})

        exported.append(rule)

    # Parse exceptions results from API return
    exceptions = []
    if export_exceptions:
        exceptions_containers = {}
        exceptions_items = {}

        exceptions_containers, exceptions_items, parse_errors, _ = parse_exceptions_results_from_api(exception_results)  # type: ignore[reportArgumentType]
        errors.extend(parse_errors)

        # Build TOMLException Objects
        exceptions, e_output, e_errors = build_exception_objects(
            exceptions_containers,
            exceptions_items,
            exception_list_rule_table,
            exceptions_directory if exceptions_directory else None,
            save_toml=False,
            skip_errors=skip_errors,
            verbose=False,
        )
        for line in e_output:
            click.echo(line)
        errors.extend(e_errors)

    # Parse action connector results from API return
    action_connectors = []
    if export_action_connectors:
        action_connector_results, _ = parse_action_connector_results_from_api(action_connector_results)  # type: ignore[reportArgumentType]

        # Build TOMLActionConnector Objects
        action_connectors, ac_output, ac_errors = build_action_connector_objects(
            action_connector_results,
            action_connector_rule_table,
            action_connectors_directory=action_connectors_directory if action_connectors_directory else None,
            save_toml=False,
            skip_errors=skip_errors,
            verbose=False,
        )
        for line in ac_output:
            click.echo(line)
        errors.extend(ac_errors)

    saved: list[TOMLRule] = []
    for rule in exported:
        try:
            rule.save_toml()
        except Exception as e:
            if skip_errors:
                print(f"- skipping {rule.contents.data.name} - {type(e).__name__}")
                errors.append(f"- {rule.contents.data.name} - {e}")
                continue
            raise

        saved.append(rule)

    saved_exceptions: list[TOMLException] = []
    for exception in exceptions:
        try:
            exception.save_toml()
        except Exception as e:
            if skip_errors:
                print(f"- skipping {exception.rule_name} - {type(e).__name__}")  # type: ignore[reportUnknownMemberType]
                errors.append(f"- {exception.rule_name} - {e}")  # type: ignore[reportUnknownMemberType]
                continue
            raise

        saved_exceptions.append(exception)

    saved_action_connectors: list[TOMLActionConnector] = []
    for action in action_connectors:
        try:
            action.save_toml()
        except Exception as e:
            if skip_errors:
                print(f"- skipping {action.name} - {type(e).__name__}")
                errors.append(f"- {action.name} - {e}")
                continue
            raise

        saved_action_connectors.append(action)

    click.echo(f"{results_len} results exported")  # type: ignore[reportUnknownArgumentType]
    click.echo(f"{len(exported)} rules converted")
    click.echo(f"{len(exceptions)} exceptions exported")
    click.echo(f"{len(action_connectors)} action connectors exported")
    click.echo(f"{len(saved)} rules saved to {directory}")
    click.echo(f"{len(saved_exceptions)} exception lists saved to {exceptions_directory}")
    click.echo(f"{len(saved_action_connectors)} action connectors saved to {action_connectors_directory}")
    if errors:
        err_file = directory / "_errors.txt"
        _ = err_file.write_text("\n".join(errors))
        click.echo(f"{len(errors)} errors saved to {err_file}")

    return exported


@kibana_group.command("search-alerts")
@click.argument("query", required=False)
@click.option("--date-range", "-d", type=(str, str), default=("now-7d", "now"), help="Date range to scope search")
@click.option("--columns", "-c", multiple=True, help="Columns to display in table")
@click.option("--extend", "-e", is_flag=True, help="If columns are specified, extend the original columns")
@click.option("--max-count", "-m", default=100, help="The max number of alerts to return")
@click.pass_context
def search_alerts(  # noqa: PLR0913
    ctx: click.Context,
    query: str,
    date_range: tuple[str, str],
    columns: list[str],
    extend: bool,
    max_count: int,
) -> None:
    """Search detection engine alerts with KQL."""
    from eql.table import Table  # type: ignore[reportMissingTypeStubs]

    from .eswrap import MATCH_ALL, add_range_to_dsl

    kibana = ctx.obj["kibana"]
    start_time, end_time = date_range
    kql_query = kql.to_dsl(query) if query else MATCH_ALL  # type: ignore[reportUnknownMemberType]
    add_range_to_dsl(kql_query["bool"].setdefault("filter", []), start_time, end_time)  # type: ignore[reportUnknownArgumentType]

    with kibana:
        alerts = [a["_source"] for a in Signal.search({"query": kql_query}, size=max_count)["hits"]["hits"]]  # type: ignore[reportUnknownMemberType]

    # check for events with nested signal fields
    if alerts:
        table_columns = ["host.hostname"]

        if "signal" in alerts[0]:
            table_columns += ["signal.rule.name", "signal.status", "signal.original_time"]
        elif "kibana.alert.rule.name" in alerts[0]:
            table_columns += ["kibana.alert.rule.name", "kibana.alert.status", "kibana.alert.original_time"]
        else:
            table_columns += ["rule.name", "@timestamp"]
        if columns:
            columns = list(columns)
            table_columns = table_columns + columns if extend else columns

        # Table requires the data to be nested, but depending on the version, some data uses dotted keys, so
        # they must be nested explicitly
        for alert in alerts:  # type: ignore[reportUnknownVariableType]
            for key in table_columns:
                if key in alert:
                    nested_set(alert, key, alert[key])  # type: ignore[reportUnknownArgumentType]

        click.echo(Table.from_list(table_columns, alerts))  # type: ignore[reportUnknownMemberType]
    else:
        click.echo("No alerts detected")
