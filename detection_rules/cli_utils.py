# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import copy
import datetime
import functools
import os
import typing
from collections.abc import Callable
from pathlib import Path
from typing import Any

import click
import kql  # type: ignore[reportMissingTypeStubs]

from . import ecs
from .attack import build_threat_map_entry, matrix, tactics
from .config import parse_rules_config
from .rule import BYPASS_VERSION_LOCK, TOMLRule, TOMLRuleContents
from .rule_loader import DEFAULT_PREBUILT_BBR_DIRS, DEFAULT_PREBUILT_RULES_DIRS, RuleCollection, dict_filter
from .schemas import definitions
from .utils import clear_caches, ensure_list_of_strings, rulename_to_filename

RULES_CONFIG = parse_rules_config()


def single_collection(f: Callable[..., Any]) -> Callable[..., Any]:
    """Add arguments to get a RuleCollection by file, directory or a list of IDs"""
    from .misc import raise_client_error

    @click.option("--rule-file", "-f", multiple=False, required=False, type=click.Path(dir_okay=False))
    @click.option("--rule-id", "-id", multiple=False, required=False)
    @functools.wraps(f)
    def get_collection(*args: Any, **kwargs: Any) -> Any:
        rule_name: list[str] = kwargs.pop("rule_name", [])
        rule_id: list[str] = kwargs.pop("rule_id", [])
        rule_files: list[str] = kwargs.pop("rule_file")
        directories: list[str] = kwargs.pop("directory")

        rules = RuleCollection()

        if bool(rule_name) + bool(rule_id) + bool(rule_files) != 1:
            raise_client_error("Required: exactly one of --rule-id, --rule-file, or --directory")

        rules.load_files(Path(p) for p in rule_files)
        rules.load_directories(Path(d) for d in directories)

        if rule_id:
            rules.load_directories(
                DEFAULT_PREBUILT_RULES_DIRS + DEFAULT_PREBUILT_BBR_DIRS, obj_filter=dict_filter(rule__rule_id=rule_id)
            )
            if len(rules) != 1:
                raise_client_error(f"Could not find rule with ID {rule_id}")

        kwargs["rules"] = rules
        return f(*args, **kwargs)

    return get_collection


def multi_collection(f: Callable[..., Any]) -> Callable[..., Any]:
    """Add arguments to get a RuleCollection by file, directory or a list of IDs"""
    from .misc import raise_client_error

    @click.option("--rule-file", "-f", multiple=True, type=click.Path(dir_okay=False), required=False)
    @click.option(
        "--directory",
        "-d",
        multiple=True,
        type=click.Path(file_okay=False),
        required=False,
        help="Recursively load rules from a directory",
    )
    @click.option("--rule-id", "-id", multiple=True, required=False)
    @click.option(
        "--no-tactic-filename",
        "-nt",
        is_flag=True,
        required=False,
        help="Allow rule filenames without tactic prefix. Use this if rules have been exported with this flag.",
    )
    @functools.wraps(f)
    def get_collection(*args: Any, **kwargs: Any) -> Any:
        rule_id: list[str] = kwargs.pop("rule_id", [])
        rule_files: list[str] = kwargs.pop("rule_file")
        directories: list[str] = kwargs.pop("directory")
        no_tactic_filename: bool = kwargs.pop("no_tactic_filename", False)

        rules = RuleCollection()

        if not (directories or rule_id or rule_files or (DEFAULT_PREBUILT_RULES_DIRS + DEFAULT_PREBUILT_BBR_DIRS)):
            raise_client_error("Required: at least one of --rule-id, --rule-file, or --directory")

        rules.load_files(Path(p) for p in rule_files)
        rules.load_directories(Path(d) for d in directories)

        if rule_id:
            rules.load_directories(
                DEFAULT_PREBUILT_RULES_DIRS + DEFAULT_PREBUILT_BBR_DIRS, obj_filter=dict_filter(rule__rule_id=rule_id)
            )
            found_ids = {rule.id for rule in rules}
            missing = set(rule_id).difference(found_ids)

            if missing:
                raise_client_error(f"Could not find rules with IDs: {', '.join(missing)}")
        elif not rule_files and not directories:
            rules.load_directories(Path(d) for d in (DEFAULT_PREBUILT_RULES_DIRS + DEFAULT_PREBUILT_BBR_DIRS))

        if len(rules) == 0:
            raise_client_error("No rules found")

        # Warn that if the path does not match the expected path, it will be saved to the expected path
        for rule in rules:
            threat = rule.contents.data.get("threat")
            first_tactic = threat[0].tactic.name if threat else ""
            # Check if flag or config is set to not include tactic in the filename
            no_tactic_filename = no_tactic_filename or RULES_CONFIG.no_tactic_filename
            tactic_name = None if no_tactic_filename else first_tactic
            rule_name = rulename_to_filename(rule.contents.data.name, tactic_name=tactic_name)
            if not rule.path:
                click.secho(f"WARNING: Rule path for rule not found: {rule_name}", fg="yellow")
            elif rule.path.name != rule_name:
                click.secho(
                    f"WARNING: Rule path does not match required path: {rule.path.name} != {rule_name}", fg="yellow"
                )

        kwargs["rules"] = rules
        return f(*args, **kwargs)

    return get_collection


def rule_prompt(  # noqa: PLR0912, PLR0913, PLR0915
    path: Path | None = None,
    rule_type: str | None = None,
    required_only: bool = True,
    save: bool = True,
    verbose: bool = False,
    additional_required: list[str] | None = None,
    skip_errors: bool = False,
    strip_none_values: bool = True,
    strip_dates: bool = False,
    **kwargs: Any,
) -> TOMLRule | str:
    """Prompt loop to build a rule."""
    from .misc import schema_prompt

    additional_required = additional_required or []
    creation_date = datetime.date.today().strftime("%Y/%m/%d")  # noqa: DTZ011
    if verbose and path:
        click.echo(f"[+] Building rule for {path}")

    kwargs = copy.deepcopy(kwargs)

    rule_name = kwargs.get("name")

    if "rule" in kwargs and "metadata" in kwargs:
        kwargs.update(kwargs.pop("metadata"))
        kwargs.update(kwargs.pop("rule"))

    rule_type_val = (
        rule_type
        or kwargs.get("type")
        or click.prompt("Rule type", type=click.Choice(typing.get_args(definitions.RuleType)))
    )

    target_data_subclass = TOMLRuleContents.get_data_subclass(rule_type_val)
    schema = target_data_subclass.jsonschema()
    props = schema["properties"]
    required_fields = schema.get("required", []) + additional_required
    contents: dict[str, Any] = {}
    skipped: list[str] = []

    for name, options in props.items():
        if name == "index" and kwargs.get("type") == "esql":
            continue

        if name == "type":
            contents[name] = rule_type_val
            continue

        # these are set at package release time depending on the version strategy
        if name in ("version", "revision") and not BYPASS_VERSION_LOCK:
            continue

        if required_only and name not in required_fields:
            continue

        # build this from technique ID
        if name == "threat":
            threat_map: list[dict[str, Any]] = []
            if not skip_errors:
                while click.confirm("add mitre tactic?"):
                    tactic = schema_prompt("mitre tactic name", type="string", enum=tactics, is_required=True)
                    technique_ids = (  # type: ignore[reportUnknownVariableType]
                        schema_prompt(
                            f"technique or sub-technique IDs for {tactic}",
                            type="array",
                            is_required=False,
                            enum=list(matrix[tactic]),
                        )
                        or []
                    )

                    try:
                        threat_map.append(build_threat_map_entry(tactic, *technique_ids))  # type: ignore[reportUnknownArgumentType]
                    except KeyError as e:
                        click.secho(f"Unknown ID: {e.args[0]} - entry not saved for: {tactic}", fg="red", err=True)
                        continue
                    except ValueError as e:
                        click.secho(f"{e} - entry not saved for: {tactic}", fg="red", err=True)
                        continue

            if len(threat_map) > 0:
                contents[name] = threat_map
            continue

        if kwargs.get(name):
            contents[name] = schema_prompt(name, value=kwargs.pop(name))
            continue

        if name == "new_terms":
            # patch to allow new_term imports
            result: dict[str, Any] = {"field": "new_terms_fields"}
            new_terms_fields_value = schema_prompt("new_terms_fields", value=kwargs.pop("new_terms_fields", None))
            result["value"] = ensure_list_of_strings(new_terms_fields_value)
            history_window_start_value = kwargs.pop("history_window_start", None)
            result["history_window_start"] = [
                {
                    "field": "history_window_start",
                    "value": schema_prompt("history_window_start", value=history_window_start_value),
                }
            ]

        elif skip_errors:
            # return missing information
            return f"Rule: {kwargs['id']}, Rule Name: {rule_name} is missing {name} information"
        else:
            result = schema_prompt(name, is_required=name in required_fields, **options.copy())
        if result:
            if name not in required_fields and result == options.get("default", ""):
                skipped.append(name)
                continue

            contents[name] = result

    # DEFAULT_PREBUILT_RULES_DIRS[0] is a required directory just as a suggestion
    suggested_path: Path = Path(DEFAULT_PREBUILT_RULES_DIRS[0]) / contents["name"]
    path = Path(path or input(f"File path for rule [{suggested_path}]: ") or suggested_path).resolve()
    # Inherit maturity and optionally local dates from the rule if it already exists
    if strip_dates:
        kwargs.pop("creation_date", None)
        kwargs.pop("updated_date", None)
    meta = {"maturity": "development"}
    if not strip_dates:
        meta["creation_date"] = kwargs.get("creation_date") or creation_date
        meta["updated_date"] = kwargs.get("updated_date") or creation_date

    try:
        rule_contents = TOMLRuleContents.from_dict({"rule": contents, "metadata": meta})
        rule = TOMLRule(path=Path(path), contents=rule_contents)
    except kql.KqlParseError as e:
        if skip_errors:
            return f"Rule: {kwargs['id']}, Rule Name: {rule_name} query failed to parse: {e.error_msg}"
        if e.error_msg == "Unknown field":
            warning = (
                f'If using a non-ECS field, you must update "ecs{os.path.sep}.non-ecs-schema.json" under `beats` or '
                "`legacy-endgame` (Non-ECS fields should be used minimally)."
            )
            click.secho(e.args[0], fg="red", err=True)
            click.secho(warning, fg="yellow", err=True)
            click.pause()

        # if failing due to a query, loop until resolved or terminated
        while True:
            try:
                contents["query"] = click.edit(contents["query"], extension=".eql")
                rule = TOMLRule(
                    path=Path(path),
                    contents=TOMLRuleContents.from_dict({"rule": contents, "metadata": meta}),
                )
            except kql.KqlParseError as e:
                click.secho(e.args[0], fg="red", err=True)
                click.pause()

                if e.error_msg.startswith("Unknown field"):  # type: ignore[reportUnknownMemberType]
                    # get the latest schema for schema errors
                    clear_caches()
                    ecs.get_kql_schema(indexes=contents.get("index", []))
                continue

            break
    except Exception as e:
        if skip_errors:
            return f"Rule: {kwargs['id']}, Rule Name: {rule_name} failed: {e}"
        raise

    if save:
        rule.save_toml(strip_none_values=strip_none_values)

    if skipped:
        print("Did not set the following values because they are un-required when set to the default value")
        print(" - {}".format("\n - ".join(skipped)))

    return rule
