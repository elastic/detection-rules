# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Kibana cli commands."""

import fnmatch
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import click
import kql  # type: ignore[reportMissingTypeStubs]
from kibana import (
    ExceptionListResource,
    RuleResource,
    Signal,
    TimelineTemplateResource,
    ValueListResource,
)  # type: ignore[reportMissingTypeStubs]

from .action_connector import (
    TOMLActionConnector,
    TOMLActionConnectorContents,
    build_action_connector_objects,
    parse_action_connector_results_from_api,
)
from .cli_utils import multi_collection
from .config import get_default_rule_dir, parse_rules_config
from .exception import (
    TOMLException,
    TOMLExceptionContents,
    build_exception_objects,
    parse_exceptions_results_from_api,
)
from .generic_loader import GenericCollection, GenericCollectionTypes
from .main import root
from .misc import add_params, get_kibana_client, kibana_options, nested_set, raise_client_error
from .rule import TOMLRule, TOMLRuleContents, downgrade_contents_from_rule
from .rule_loader import RawRuleCollection, RuleCollection, update_metadata_from_file
from .schemas import definitions  # noqa: TC001
from .timeline import TOMLTimelineTemplate, TOMLTimelineTemplateContents
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
@click.option(
    "--overwrite-exceptions",
    "-e",
    is_flag=True,
    help="Overwrite existing exception lists (otherwise they are skipped)",
)
@click.option(
    "--overwrite-action-connectors",
    "-ac",
    is_flag=True,
    help="Overwrite action connectors in existing rules",
)
@click.option(
    "--overwrite-value-lists",
    "-vl",
    is_flag=True,
    help="Overwrite value lists referenced in exceptions",
)
@click.option(
    "--overwrite-timeline-templates",
    "-tt",
    is_flag=True,
    help="Overwrite timeline templates referenced in rules",
)
@click.option(
    "--exclude-exceptions",
    "-ee",
    multiple=True,
    help="Exclude exception lists by name (supports wildcards)",
)
@click.pass_context
def kibana_import_rules(  # noqa: PLR0912, PLR0913, PLR0915
    ctx: click.Context,
    rules: RuleCollection,
    overwrite: bool = False,
    overwrite_exceptions: bool = False,
    overwrite_action_connectors: bool = False,
    overwrite_value_lists: bool = False,
    overwrite_timeline_templates: bool = False,
    exclude_exceptions: tuple[str, ...] = (),
) -> tuple[dict[str, Any], list[RuleResource]]:
    """Import custom rules into Kibana.

    The code below breaks the workflow into
    small, well documented helper functions that closely mirror the required
    import phases.  Each phase focuses on a single responsibility which makes
    the data dependencies explicit and greatly simplifies future changes.
    """

    # ------------------------------------------------------------------
    # Helper data structures
    # ------------------------------------------------------------------

    @dataclass
    class ItemLog:
        """Small container to keep track of name/id/message triples."""

        name: str
        identifier: str
        message: str | None = None

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _matches_rule_ids(item: GenericCollectionTypes, rule_ids: set[str]) -> bool:
        """Return True when a TOML object belongs to one of the rules."""

        return any(rule_id in rule_ids for rule_id in item.contents.metadata.get("rule_ids", []))

    def _format_item(item: ItemLog) -> str:
        """Format a log entry as 'name - id' with optional message."""

        base = f"{item.name} - {item.identifier}"
        return f"{base}: {item.message}" if item.message else base

    def _suggest_reimport(response: dict[str, Any]) -> None:
        """Provide re-import hints for known transient failures."""

        def _parse_list_id(msg: str) -> str | None:
            match = re.search(r'list_id: "(.*?)"', msg)
            return match.group(1) if match else None

        workaround_ids: list[str] = []
        workaround_types: set[str] = set()
        flattened = [e for sub in exception_dicts for e in sub]
        all_list_ids = {e["list_id"] for e in flattened}

        connector_validation_error = "Error validating create data"
        connector_type_error = "expected value of type [string] but got [undefined]"

        for error in response.get("errors", []):
            message = error["error"]["message"]
            if "references a non existent exception list" in message:
                list_id = _parse_list_id(message)
                if list_id in all_list_ids:
                    workaround_ids.append(error["rule_id"])
                    workaround_types.add("non existent exception list")
            if connector_validation_error in message and connector_type_error in message:
                workaround_types.add("connector still being built")

        if workaround_ids:
            workaround_ids = list(set(workaround_ids))
            if "non existent exception list" in workaround_types:
                click.echo(
                    f"Missing exception list errors detected for {len(workaround_ids)} rules. "
                    "Try re-importing using the following command and rule IDs:\n",
                )
                click.echo("python -m detection_rules kibana import-rules -o ", nl=False)
                click.echo(" ".join(f"-id {r_id}" for r_id in workaround_ids))
                click.echo()
            if "connector still being built" in workaround_types:
                click.echo(
                    f"Connector still being built errors detected for {len(workaround_ids)} rules. "
                    "Please try re-importing the rules again.",
                )
                click.echo()

    # ------------------------------------------------------------------
    # Phase 1 - prepare rule payloads and collect referenced objects
    # ------------------------------------------------------------------

    kibana = ctx.obj["kibana"]

    # Convert the TOML rule objects into dictionaries understood by the API
    rule_dicts = [r.contents.to_api_format() for r in rules]

    # Keep a mapping of rule_id -> rule_name for nicer logging later on
    rule_id_name_map = {r["rule_id"]: r["name"] for r in rule_dicts}

    # Collect identifiers for quick membership checks during dependency
    # resolution.  ``timeline_ids`` is used when importing timeline templates.
    rule_ids = set(rule_id_name_map)
    timeline_ids = {r["timeline_id"] for r in rule_dicts if r.get("timeline_id")}

    # Load all supporting TOML resources (exceptions, connectors, templates)
    # from the repository.  We use a generic loader which crawls the default
    # directories and yields strongly typed objects.
    cl = GenericCollection.default()

    # Track which items should actually be imported.  The structures below are
    # filled in the collection loop and later consumed by the individual
    # import phases.
    exception_map: dict[str, tuple[str, list[dict[str, Any]]]] = {}
    action_connectors: list[list[dict[str, Any]]] = []
    timeline_template_map: dict[str, tuple[str, dict[str, Any]]] = {}

    # Exception lists can be excluded via patterns.  Pre-compile the regexes so
    # the check is cheap when walking through the loaded objects.
    exclusion_regexes = [re.compile(fnmatch.translate(p), re.IGNORECASE) for p in exclude_exceptions]

    def _is_excluded(name: str) -> bool:
        """Return True when a list name matches any exclusion pattern."""

        return any(rx.match(name) for rx in exclusion_regexes)

    # Lists that were excluded completely.  We record both name and id so we
    # can present a user friendly summary at the end of the run.
    excluded_lists: list[ItemLog] = []
    excluded_list_ids: set[str] = set()

    for item in cl.items:
        # Handle exception lists that are referenced by the selected rules
        if isinstance(item.contents, TOMLExceptionContents) and _matches_rule_ids(item, rule_ids):
            name = item.contents.metadata.list_name
            edicts = item.contents.to_api_format()
            list_id = edicts[0]["list_id"]
            if _is_excluded(name):
                excluded_lists.append(ItemLog(name=name, identifier=list_id))
                excluded_list_ids.add(list_id)
                continue
            exception_map[list_id] = (name, edicts)

        # Gather action connectors referenced by the rules.  They will be
        # bundled into the rule import request later on.
        elif isinstance(item.contents, TOMLActionConnectorContents) and _matches_rule_ids(item, rule_ids):
            action_connectors.append(item.contents.to_api_format())

        # Capture timeline templates so they can be imported before the rules
        elif isinstance(item.contents, TOMLTimelineTemplateContents):
            t_id = item.contents.metadata.timeline_template_id
            if t_id in timeline_ids:
                title = item.contents.metadata.timeline_template_title
                timeline_template_map[t_id] = (title, item.contents.to_api_format())

    # Remove references to excluded exception lists from the rule payloads so
    # Kibana never sees them during import.
    if excluded_list_ids:
        for rd in rule_dicts:
            if "exceptions_list" in rd:
                rd["exceptions_list"] = [e for e in rd["exceptions_list"] if e.get("list_id") not in excluded_list_ids]

    # ------------------------------------------------------------------
    # The remaining phases communicate with Kibana and therefore require the
    # API client context.  All network requests are performed within the
    # ``with kibana`` block so that the helper functions in ``resources.py``
    # can access the active client via ``Kibana.current()``.
    # ------------------------------------------------------------------

    with kibana:
        # ------------------------------------------------------------------
        # Phase 2 - prepare exception list import and collect value list IDs
        # ------------------------------------------------------------------

        def _collect_list_ids(entries: list[dict[str, Any]], dest: dict[str, tuple[str, str]]) -> None:
            """Recursively collect value list IDs used by exception entries."""

            for entry in entries:
                if entry.get("type") == "list" and entry.get("list"):
                    list_id = entry["list"]["id"]
                    list_type = entry["list"].get("type", "keyword")
                    dest[list_id] = (list_type, list_id)  # name defaults to ID
                elif entry.get("type") == "nested":
                    _collect_list_ids(entry.get("entries", []), dest)

        exception_dicts: list[list[dict[str, Any]]] = []
        exception_imported: list[ItemLog] = []
        skipped_exception_lists: list[ItemLog] = []
        failed_exception_lists: list[ItemLog] = []
        value_list_map: dict[str, tuple[str, str]] = {}

        for list_id, (name, edicts) in exception_map.items():
            try:
                existing = ExceptionListResource.get(list_id)
            except Exception as exc:  # noqa: BLE001
                failed_exception_lists.append(ItemLog(name, list_id, str(exc)))
                continue
            if existing and not overwrite_exceptions:
                skipped_exception_lists.append(ItemLog(name, list_id))
                continue
            for item in edicts:
                _collect_list_ids(item.get("entries", []), value_list_map)
            exception_dicts.append(edicts)
            exception_imported.append(ItemLog(name, list_id))

        # ------------------------------------------------------------------
        # Phase 3 - import required value lists
        # ------------------------------------------------------------------

        imported_value_lists: list[ItemLog] = []
        skipped_value_lists: list[ItemLog] = []
        missing_value_lists: list[ItemLog] = []
        failed_value_lists: list[ItemLog] = []

        value_list_dir = RULES_CONFIG.value_list_dir
        if value_list_map:
            try:
                ValueListResource.create_index()
            except Exception as exc:  # noqa: BLE001
                failed_value_lists.append(ItemLog("index", "value-lists", f"Failed to create: {exc}"))

        for list_id, (list_type, name) in value_list_map.items():
            file_path = value_list_dir / list_id if value_list_dir else None
            if not file_path or not file_path.exists():
                missing_value_lists.append(ItemLog(name, list_id))
                continue
            text = file_path.read_text()
            try:
                existing = ValueListResource.get(list_id)
            except Exception as exc:  # noqa: BLE001
                failed_value_lists.append(ItemLog(name, list_id, str(exc)))
                continue
            if existing and not overwrite_value_lists:
                skipped_value_lists.append(ItemLog(name, list_id))
                continue
            if existing and overwrite_value_lists:
                try:
                    ValueListResource.delete_list_items(list_id)
                except Exception as exc:  # noqa: BLE001
                    failed_value_lists.append(ItemLog(name, list_id, str(exc)))
                    continue
            else:
                try:
                    ValueListResource.create(list_id, list_type, name)
                except Exception as exc:  # noqa: BLE001
                    failed_value_lists.append(ItemLog(name, list_id, str(exc)))
                    continue
            try:
                ValueListResource.import_list_items(list_id, text, list_type)
            except Exception as exc:  # noqa: BLE001
                failed_value_lists.append(ItemLog(name, list_id, str(exc)))
                continue
            imported_value_lists.append(ItemLog(name, list_id))

        # ------------------------------------------------------------------
        # Phase 4 - import timeline templates
        # ------------------------------------------------------------------

        imported_timeline_templates: list[ItemLog] = []
        skipped_timeline_templates: list[ItemLog] = []
        missing_timeline_templates: list[ItemLog] = []
        failed_timeline_templates: list[ItemLog] = []

        for t_id in timeline_ids:
            title, payload = timeline_template_map.get(t_id, (t_id, None))
            if payload is None:
                missing_timeline_templates.append(ItemLog(title, t_id))
                continue
            try:
                existing = TimelineTemplateResource.get(t_id)
            except Exception as exc:  # noqa: BLE001
                failed_timeline_templates.append(ItemLog(title, t_id, str(exc)))
                continue
            if existing and not overwrite_timeline_templates:
                skipped_timeline_templates.append(ItemLog(title, t_id))
                continue
            if existing and overwrite_timeline_templates:
                try:
                    existing_version = existing.get("templateTimelineVersion") if isinstance(existing, dict) else None
                    if isinstance(existing_version, int):
                        payload["templateTimelineVersion"] = existing_version + 1
                    else:
                        TimelineTemplateResource.delete(t_id)
                    TimelineTemplateResource.import_template(json.dumps(payload))
                except Exception as exc:  # noqa: BLE001
                    failed_timeline_templates.append(ItemLog(title, t_id, str(exc)))
                    continue
            else:
                try:
                    TimelineTemplateResource.import_template(json.dumps(payload))
                except Exception as exc:  # noqa: BLE001
                    failed_timeline_templates.append(ItemLog(title, t_id, str(exc)))
                    continue
            imported_timeline_templates.append(ItemLog(title, t_id))

        # ------------------------------------------------------------------
        # Phase 5 - import rules, exceptions and action connectors
        # ------------------------------------------------------------------

        response, rule_resources = RuleResource.import_rules(
            rule_dicts,
            exception_dicts,
            action_connectors,
            overwrite=overwrite,
            overwrite_exceptions=overwrite_exceptions,
            overwrite_action_connectors=overwrite_action_connectors,
        )

        successful_rules = [ItemLog(r.get("name", r.get("rule_id", "")), r.get("rule_id", "")) for r in rule_resources]

        error_items: list[ItemLog] = []
        if response.get("errors"):
            for error in response["errors"]:
                r_id = error.get("rule_id", "")
                name = rule_id_name_map.get(r_id, r_id)
                msg = f"({error['error']['status_code']}) {error['error']['message']}"
                error_items.append(ItemLog(name, r_id, msg))

    # ------------------------------------------------------------------
    # Final logging
    # ------------------------------------------------------------------

    if successful_rules:
        click.echo(f"{len(successful_rules)} rule(s) successfully imported")
        click.echo("\n".join(f" - {_format_item(r)}" for r in successful_rules))
    if error_items:
        click.echo(f"{len(error_items)} rule(s) failed to import!")
        click.echo("\n".join(f" - {_format_item(e)}" for e in error_items))
        _suggest_reimport(response)
    else:
        if exception_imported:
            click.echo(f"{len(exception_imported)} exception list(s) successfully imported")
            click.echo("\n".join(f" - {_format_item(i)}" for i in exception_imported))
        if action_connectors:
            connector_logs = [
                ItemLog(c.get("name", c.get("id", "")), c.get("id", "")) for group in action_connectors for c in group
            ]
            if connector_logs:
                click.echo(f"{len(connector_logs)} action connector(s) successfully imported")
                click.echo("\n".join(f" - {_format_item(c)}" for c in connector_logs))

    if excluded_lists:
        click.echo("Exception lists excluded from import:")
        click.echo("\n".join(f" - {_format_item(e)}" for e in excluded_lists))
    if skipped_exception_lists:
        click.echo("Exception lists already exist and were not overwritten:")
        click.echo("\n".join(f" - {_format_item(s)}" for s in skipped_exception_lists))
    if failed_exception_lists:
        click.echo("Exception list errors:")
        click.echo("\n".join(f" - {_format_item(f)}" for f in failed_exception_lists))

    if imported_value_lists:
        click.echo(f"{len(imported_value_lists)} value list(s) successfully imported")
        click.echo("\n".join(f" - {_format_item(v)}" for v in imported_value_lists))
    if skipped_value_lists:
        click.echo("Value lists already exist and were not overwritten:")
        click.echo("\n".join(f" - {_format_item(v)}" for v in skipped_value_lists))
    if missing_value_lists:
        click.echo("Value list files not found:")
        click.echo("\n".join(f" - {_format_item(v)}" for v in missing_value_lists))
    if failed_value_lists:
        click.echo("Value list errors:")
        click.echo("\n".join(f" - {_format_item(v)}" for v in failed_value_lists))

    if imported_timeline_templates:
        click.echo(f"{len(imported_timeline_templates)} timeline template(s) successfully imported")
        click.echo("\n".join(f" - {_format_item(t)}" for t in imported_timeline_templates))
    if skipped_timeline_templates:
        click.echo("Timeline templates already exist and were not overwritten:")
        click.echo("\n".join(f" - {_format_item(t)}" for t in skipped_timeline_templates))
    if missing_timeline_templates:
        click.echo("Timeline template files not found:")
        click.echo("\n".join(f" - {_format_item(t)}" for t in missing_timeline_templates))
    if failed_timeline_templates:
        click.echo("Timeline template errors:")
        click.echo("\n".join(f" - {_format_item(t)}" for t in failed_timeline_templates))

    return response, rule_resources


@kibana_group.command("export-rules")
@click.option("--directory", "-d", required=False, type=Path, help="Directory to export rules to")
@click.option(
    "--action-connectors-directory", "-acd", required=False, type=Path, help="Directory to export action connectors to"
)
@click.option("--exceptions-directory", "-ed", required=False, type=Path, help="Directory to export exceptions to")
@click.option("--value-list-directory", "-vld", required=False, type=Path, help="Directory to export value lists to")
@click.option(
    "--timeline-templates-directory",
    "-ttd",
    required=False,
    type=Path,
    help="Directory to export timeline templates to",
)
@click.option("--default-author", "-da", type=str, required=False, help="Default author for rules missing one")
@click.option("--rule-id", "-r", multiple=True, help="Optional Rule IDs to restrict export to")
@click.option(
    "--rule-name",
    "-rn",
    multiple=True,
    required=False,
    help=(
        "Optional Rule name to restrict export to (KQL, case-insensitive, supports wildcards). "
        "May be specified multiple times."
    ),
)
@click.option("--export-action-connectors", "-ac", is_flag=True, help="Include action connectors in export")
@click.option("--export-exceptions", "-e", is_flag=True, help="Include exceptions in export")
@click.option("--export-value-lists", "-vl", is_flag=True, help="Include value lists referenced in exceptions")
@click.option(
    "--export-timeline-templates",
    "-tt",
    is_flag=True,
    help="Include timeline templates referenced in rules",
)
@click.option("--skip-errors", "-s", is_flag=True, help="Skip errors when exporting rules")
@click.option("--strip-version", "-sv", is_flag=True, help="Strip the version fields from all rules")
@click.option("--strip-dates", "-sd", is_flag=True, help="Strip creation and updated date fields from exported rules")
@click.option("--strip-exception-list-id", "-sli", is_flag=True, help="Strip id fields from rule exceptions list")
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
    directory: Path | None,
    action_connectors_directory: Path | None,
    exceptions_directory: Path | None,
    value_list_directory: Path | None,
    timeline_templates_directory: Path | None,
    default_author: str,
    rule_id: list[str] | None = None,
    rule_name: list[str] | None = None,
    export_action_connectors: bool = False,
    export_exceptions: bool = False,
    export_value_lists: bool = False,
    export_timeline_templates: bool = False,
    skip_errors: bool = False,
    strip_version: bool = False,
    strip_dates: bool = False,
    strip_exception_list_id: bool = False,
    no_tactic_filename: bool = False,
    local_creation_date: bool = False,
    local_updated_date: bool = False,
    custom_rules_only: bool = False,
    export_query: str | None = None,
    load_rule_loading: bool = False,
) -> list[TOMLRule]:
    """Export custom rules from Kibana."""
    directory = directory or get_default_rule_dir()
    if directory is None:
        raise click.UsageError("No directory specified and no rule_dirs configured")

    kibana = ctx.obj["kibana"]
    strip_version = strip_version or RULES_CONFIG.strip_version
    strip_dates = strip_dates or RULES_CONFIG.strip_dates
    strip_exception_list_id = strip_exception_list_id or RULES_CONFIG.strip_exception_list_id
    default_author = default_author or RULES_CONFIG.default_author
    if export_value_lists and not export_exceptions:
        raise click.UsageError("--export-value-lists requires --export-exceptions")
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
            found_ids: list[str] = []
            for name in rule_name:
                found = RuleResource.find(filter=f"alert.attributes.name:{name}")  # type: ignore[reportUnknownMemberType]
                found_ids.extend([r["rule_id"] for r in found])  # type: ignore[reportUnknownVariableType]
            rule_id = list(dict.fromkeys(found_ids))
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

    # Handle Value List Directory Location
    if results and value_list_directory:
        value_list_directory.mkdir(parents=True, exist_ok=True)
    value_list_directory = value_list_directory or RULES_CONFIG.value_list_dir
    if not value_list_directory and export_value_lists:
        click.echo("Warning: Value list export requested, but no Value list directory found")

    # Handle Timeline Template Directory Location
    if results and timeline_templates_directory:
        timeline_templates_directory.mkdir(parents=True, exist_ok=True)
    timeline_templates_directory = timeline_templates_directory or RULES_CONFIG.timeline_template_dir
    if not timeline_templates_directory and export_timeline_templates:
        click.echo("Warning: Timeline template export requested, but no Timeline template directory found")

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

    # ------------------------------------------------------------------
    # Helper data structures for consistent log formatting
    # ------------------------------------------------------------------

    @dataclass
    class ItemLog:
        """Container for human friendly log output."""

        name: str  # human readable name of the item
        identifier: str  # unique identifier such as id or list_id
        message: str | None = None  # optional error message

    def _format_item(item: ItemLog) -> str:
        """Return a standardized 'name - id' string with optional message."""

        base = f"{item.name} - {item.identifier}"
        return f"{base}: {item.message}" if item.message else base

    # Keep a running list of errors for the final summary report
    errors: list[str] = []
    # Store exported rule objects for later processing and logging
    exported: list[TOMLRule] = []
    exception_list_rule_table: dict[str, list[dict[str, Any]]] = {}
    action_connector_rule_table: dict[str, list[dict[str, Any]]] = {}
    value_list_ids: set[str] = set()  # value lists referenced across all exceptions
    timeline_ids: set[str] = set()  # timeline templates referenced by rules

    # Collect detailed logs for rules and dependent resources
    rule_logs: list[ItemLog] = []
    rule_error_logs: list[ItemLog] = []
    exception_logs: list[ItemLog] = []
    exception_error_logs: list[ItemLog] = []
    action_logs: list[ItemLog] = []
    action_error_logs: list[ItemLog] = []
    value_list_logs: list[ItemLog] = []
    value_list_error_logs: list[ItemLog] = []
    timeline_logs: list[ItemLog] = []
    timeline_error_logs: list[ItemLog] = []

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
            if strip_dates:
                params["creation_date"] = None
                params["updated_date"] = None
            contents = TOMLRuleContents.from_rule_resource(**params)  # type: ignore[reportArgumentType]
            rule = TOMLRule(contents=contents, path=save_path)
            if strip_exception_list_id and rule.contents.data.exceptions_list:
                for exc in rule.contents.data.exceptions_list:
                    exc.pop("id", None)
        except Exception as e:
            if skip_errors:
                name = cast("str", rule_resource.get("name", "unknown"))
                rule_id = cast("str", rule_resource.get("rule_id", "unknown"))
                print(f"- skipping {name} - {rule_id} - {type(e).__name__}")
                errors.append(f"- {name} - {rule_id} - {e}")
                rule_error_logs.append(ItemLog(name, rule_id, str(e)))
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

        if export_timeline_templates:
            # Collect timeline IDs in this initial pass, alongside exception and action connector data,
            # so we only walk the rules once before exporting templates later.
            t_id = rule.contents.data.timeline_id  # type: ignore[reportUnknownMemberType]
            if t_id:
                timeline_ids.add(t_id)

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
            strip_dates=strip_dates,
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
            strip_dates=strip_dates,
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
                print(f"- skipping {rule.name} - {rule.id} - {type(e).__name__}")
                errors.append(f"- {rule.name} - {rule.id} - {e}")
                rule_error_logs.append(ItemLog(rule.name, rule.id, str(e)))
                continue
            raise

        saved.append(rule)
        rule_logs.append(ItemLog(rule.name, rule.id))

    saved_exceptions: list[TOMLException] = []

    # Recursively walk exception entries and record any referenced value list IDs
    def _collect_list_ids(entries: list[dict[str, Any]]) -> None:
        for entry in entries:
            if entry.get("type") == "list" and entry.get("list"):
                value_list_ids.add(entry["list"]["id"])
            elif entry.get("type") == "nested":
                _collect_list_ids(entry.get("entries", []))

    for exception in exceptions:
        try:
            exception.save_toml()
        except Exception as e:
            if skip_errors:
                list_id = exception.contents.exceptions[0].container.list_id  # type: ignore[reportUnknownMemberType]
                name = exception.name
                print(f"- skipping {name} - {list_id} - {type(e).__name__}")
                errors.append(f"- {name} - {list_id} - {e}")
                exception_error_logs.append(ItemLog(name, list_id, str(e)))
                continue
            raise

        saved_exceptions.append(exception)
        list_id = exception.contents.exceptions[0].container.list_id  # type: ignore[reportUnknownMemberType]
        exception_logs.append(ItemLog(exception.name, list_id))
        if export_value_lists:
            # Gather list IDs for each successfully saved exception
            list_id = exception.contents.exceptions[0].container.list_id  # type: ignore[reportUnknownMemberType]
            for item in exceptions_items.get(list_id, []):
                _collect_list_ids(item.get("entries", []))

    value_list_exported: list[str] = []
    saved_value_lists: list[str] = []
    # Export each collected value list from Kibana and write to disk once
    if export_value_lists and value_list_ids:
        with kibana:
            for list_id in sorted(value_list_ids):
                try:
                    # Call Kibana API to fetch the list's items in export format
                    text = ValueListResource.export_list_items(list_id)
                    value_list_exported.append(list_id)
                    value_list_logs.append(ItemLog(list_id, list_id))
                    if value_list_directory:
                        (value_list_directory / list_id).write_text(text)
                        saved_value_lists.append(list_id)
                except Exception as e:
                    if skip_errors:
                        print(f"- skipping {list_id} - {list_id} - {type(e).__name__}")
                        errors.append(f"- {list_id} - {list_id} - {e}")
                        value_list_error_logs.append(ItemLog(list_id, list_id, str(e)))
                        continue
                    raise

    timeline_template_exported: list[str] = []
    saved_timeline_templates: list[str] = []
    if export_timeline_templates and timeline_ids:
        with kibana:
            for t_id in sorted(timeline_ids):
                try:
                    payload = TimelineTemplateResource.export_template(t_id)

                    # Optionally strip version and date fields from the exported JSON
                    if strip_version:
                        payload.pop("version", None)
                        payload.pop("templateTimelineVersion", None)
                    if strip_dates:
                        payload.pop("created", None)
                        payload.pop("updated", None)
                    contents = TOMLTimelineTemplateContents.from_timeline_dict(payload, strip_dates=strip_dates)
                    tt_object = TOMLTimelineTemplate(
                        contents=contents,
                        path=(
                            timeline_templates_directory / f"{t_id}.toml"
                            if timeline_templates_directory
                            else Path(f"{t_id}.toml")
                        ),
                    )
                    timeline_template_exported.append(t_id)
                    if timeline_templates_directory:
                        tt_object.save_toml()
                        saved_timeline_templates.append(t_id)
                    title = tt_object.contents.metadata.timeline_template_title
                    timeline_logs.append(ItemLog(title, t_id))
                except Exception as e:
                    if skip_errors:
                        print(f"- skipping {t_id} - {t_id} - {type(e).__name__}")
                        errors.append(f"- {t_id} - {t_id} - {e}")
                        timeline_error_logs.append(ItemLog(t_id, t_id, str(e)))
                        continue
                    raise

    saved_action_connectors: list[TOMLActionConnector] = []
    for action in action_connectors:
        action_id = action.contents.action_connectors[0].id  # type: ignore[reportUnknownMemberType]
        try:
            action.save_toml()
        except Exception as e:
            if skip_errors:
                print(f"- skipping {action.name} - {action_id} - {type(e).__name__}")
                errors.append(f"- {action.name} - {action_id} - {e}")
                action_error_logs.append(ItemLog(action.name, action_id, str(e)))
                continue
            raise

        saved_action_connectors.append(action)
        action_logs.append(ItemLog(action.name, action_id))

    click.echo(f"{results_len} results exported")  # type: ignore[reportUnknownArgumentType]
    click.echo(f"{len(exported)} rules converted")
    click.echo(f"{len(exceptions)} exceptions exported")
    click.echo(f"{len(action_connectors)} action connectors exported")
    click.echo(f"{len(value_list_exported)} value lists exported")
    click.echo(f"{len(timeline_template_exported)} timeline templates exported")
    click.echo(f"{len(saved)} rules saved to {directory}")
    click.echo(f"{len(saved_exceptions)} exception lists saved to {exceptions_directory}")
    click.echo(f"{len(saved_action_connectors)} action connectors saved to {action_connectors_directory}")
    click.echo(f"{len(saved_value_lists)} value lists saved to {value_list_directory}")
    click.echo(f"{len(saved_timeline_templates)} timeline templates saved to {timeline_templates_directory}")

    # ------------------------------------------------------------------
    # Detailed log output for saved and skipped items
    # ------------------------------------------------------------------
    if rule_logs:
        click.echo("\nRules saved:")
        click.echo("\n".join(f" - {_format_item(r)}" for r in rule_logs))
    if rule_error_logs:
        click.echo("\nRules skipped:")
        click.echo("\n".join(f" - {_format_item(r)}" for r in rule_error_logs))

    if exception_logs:
        click.echo("\nExceptions saved:")
        click.echo("\n".join(f" - {_format_item(e)}" for e in exception_logs))
    if exception_error_logs:
        click.echo("\nExceptions skipped:")
        click.echo("\n".join(f" - {_format_item(e)}" for e in exception_error_logs))

    if action_logs:
        click.echo("\nAction connectors saved:")
        click.echo("\n".join(f" - {_format_item(a)}" for a in action_logs))
    if action_error_logs:
        click.echo("\nAction connectors skipped:")
        click.echo("\n".join(f" - {_format_item(a)}" for a in action_error_logs))

    if value_list_logs:
        click.echo("\nValue lists saved:")
        click.echo("\n".join(f" - {_format_item(v)}" for v in value_list_logs))
    if value_list_error_logs:
        click.echo("\nValue lists skipped:")
        click.echo("\n".join(f" - {_format_item(v)}" for v in value_list_error_logs))

    if timeline_logs:
        click.echo("\nTimeline templates saved:")
        click.echo("\n".join(f" - {_format_item(t)}" for t in timeline_logs))
    if timeline_error_logs:
        click.echo("\nTimeline templates skipped:")
        click.echo("\n".join(f" - {_format_item(t)}" for t in timeline_error_logs))
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
