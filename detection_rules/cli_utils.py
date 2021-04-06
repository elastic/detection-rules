# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import copy
import datetime
import os
import typing
from pathlib import Path
from typing import List

import click

import kql
import functools
from . import ecs
from .attack import matrix, tactics, build_threat_map_entry
from .rule import TOMLRule, TOMLRuleContents
from .rule_loader import RuleCollection, DEFAULT_RULES_DIR, dict_filter
from .schemas import definitions
from .utils import clear_caches, get_path

RULES_DIR = get_path("rules")


def single_collection(f):
    """Add arguments to get a RuleCollection by file, directory or a list of IDs"""
    from .misc import client_error

    @click.option('--rule-file', '-f', multiple=False, required=False, type=click.Path(dir_okay=False))
    @click.option('--rule-id', '-id', multiple=False, required=False)
    @functools.wraps(f)
    def get_collection(*args, **kwargs):
        rule_name: List[str] = kwargs.pop("rule_name", [])
        rule_id: List[str] = kwargs.pop("rule_id", [])
        rule_files: List[str] = kwargs.pop("rule_file")
        directories: List[str] = kwargs.pop("directory")

        rules = RuleCollection()

        if bool(rule_name) + bool(rule_id) + bool(rule_files) != 1:
            client_error('Required: exactly one of --rule-id, --rule-file, or --directory')

        rules.load_files(Path(p) for p in rule_files)
        rules.load_directories(Path(d) for d in directories)

        if rule_id:
            rules.load_directory(DEFAULT_RULES_DIR, toml_filter=dict_filter(rule__rule_id=rule_id))

            if len(rules) != 1:
                client_error(f"Could not find rule with ID {rule_id}")

        kwargs["rules"] = rules
        return f(*args, **kwargs)

    return get_collection


def multi_collection(f):
    """Add arguments to get a RuleCollection by file, directory or a list of IDs"""
    from .misc import client_error

    @click.option('--rule-file', '-f', multiple=True, type=click.Path(dir_okay=False), required=False)
    @click.option('--directory', '-d', multiple=True, type=click.Path(file_okay=False), required=False,
                  help='Recursively export rules from a directory')
    @click.option('--rule-id', '-id', multiple=True, required=False)
    @functools.wraps(f)
    def get_collection(*args, **kwargs):
        rule_name: List[str] = kwargs.pop("rule_name", [])
        rule_id: List[str] = kwargs.pop("rule_id", [])
        rule_files: List[str] = kwargs.pop("rule_file")
        directories: List[str] = kwargs.pop("directory")

        rules = RuleCollection()

        if not rule_name or rule_id or rule_files:
            client_error('Required: at least one of --rule-id, --rule-file, or --directory')

        rules.load_files(Path(p) for p in rule_files)
        rules.load_directories(Path(d) for d in directories)

        if rule_id:
            rules.load_directory(DEFAULT_RULES_DIR, toml_filter=dict_filter(rule__rule_id=rule_id))
            found_ids = {rule.id for rule in rules}
            missing = set(rule_id).difference(found_ids)

            if missing:
                client_error(f'Could not find rules with IDs: {", ".join(missing)}')

        if len(rules) == 0:
            client_error("No rules found")

        kwargs["rules"] = rules
        return f(*args, **kwargs)

    return get_collection


def rule_prompt(path=None, rule_type=None, required_only=True, save=True, verbose=False, **kwargs) -> TOMLRule:
    """Prompt loop to build a rule."""
    from .misc import schema_prompt

    creation_date = datetime.date.today().strftime("%Y/%m/%d")
    if verbose and path:
        click.echo(f'[+] Building rule for {path}')

    kwargs = copy.deepcopy(kwargs)

    if 'rule' in kwargs and 'metadata' in kwargs:
        kwargs.update(kwargs.pop('metadata'))
        kwargs.update(kwargs.pop('rule'))

    rule_type = rule_type or kwargs.get('type') or \
        click.prompt('Rule type', type=click.Choice(typing.get_args(definitions.RuleType)))

    target_data_subclass = TOMLRuleContents.get_data_subclass(rule_type)
    schema = target_data_subclass.jsonschema()
    props = schema['properties']
    opt_reqs = schema.get('required', [])
    contents = {}
    skipped = []

    for name, options in props.items():

        if name == 'type':
            contents[name] = rule_type
            continue

        # these are set at package release time
        if name == 'version':
            continue

        if required_only and name not in opt_reqs:
            continue

        # build this from technique ID
        if name == 'threat':
            threat_map = []

            while click.confirm('add mitre tactic?'):
                tactic = schema_prompt('mitre tactic name', type='string', enum=tactics, required=True)
                technique_ids = schema_prompt(f'technique or sub-technique IDs for {tactic}', type='array',
                                              required=False, enum=list(matrix[tactic])) or []

                try:
                    threat_map.append(build_threat_map_entry(tactic, *technique_ids))
                except KeyError as e:
                    click.secho(f'Unknown ID: {e.args[0]} - entry not saved for: {tactic}', fg='red', err=True)
                    continue
                except ValueError as e:
                    click.secho(f'{e} - entry not saved for: {tactic}', fg='red', err=True)
                    continue

            if len(threat_map) > 0:
                contents[name] = threat_map
            continue

        if name == 'threshold':
            contents[name] = {n: schema_prompt(f'threshold {n}', required=n in options['required'], **opts.copy())
                              for n, opts in options['properties'].items()}
            continue

        if kwargs.get(name):
            contents[name] = schema_prompt(name, value=kwargs.pop(name))
            continue

        result = schema_prompt(name, required=name in opt_reqs, **options.copy())

        if result:
            if name not in opt_reqs and result == options.get('default', ''):
                skipped.append(name)
                continue

            contents[name] = result

    suggested_path = os.path.join(RULES_DIR, contents['name'])  # TODO: UPDATE BASED ON RULE STRUCTURE
    path = os.path.realpath(path or input('File path for rule [{}]: '.format(suggested_path)) or suggested_path)
    meta = {'creation_date': creation_date, 'updated_date': creation_date, 'maturity': 'development'}

    try:
        rule = TOMLRule(path=Path(path), contents=TOMLRuleContents.from_dict({'rule': contents, 'metadata': meta}))
    except kql.KqlParseError as e:
        if e.error_msg == 'Unknown field':
            warning = ('If using a non-ECS field, you must update "ecs{}.non-ecs-schema.json" under `beats` or '
                       '`legacy-endgame` (Non-ECS fields should be used minimally).'.format(os.path.sep))
            click.secho(e.args[0], fg='red', err=True)
            click.secho(warning, fg='yellow', err=True)
            click.pause()

        # if failing due to a query, loop until resolved or terminated
        while True:
            try:
                contents['query'] = click.edit(contents['query'], extension='.eql')
                rule = TOMLRule(path=Path(path),
                                contents=TOMLRuleContents.from_dict({'rule': contents, 'metadata': meta}))
            except kql.KqlParseError as e:
                click.secho(e.args[0], fg='red', err=True)
                click.pause()

                if e.error_msg.startswith("Unknown field"):
                    # get the latest schema for schema errors
                    clear_caches()
                    ecs.get_kql_schema(indexes=contents.get("index", []))
                continue

            break

    if save:
        rule.save_toml()

    if skipped:
        print('Did not set the following values because they are un-required when set to the default value')
        print(' - {}'.format('\n - '.join(skipped)))

    # rta_mappings.add_rule_to_mapping_file(rule)
    # click.echo('Placeholder added to rule-mapping.yml')

    click.echo('Rule will validate against the latest ECS schema available (and beats if necessary)')
    click.echo('    - to have a rule validate against specific ECS schemas, add them to metadata->ecs_versions')
    click.echo('    - to have a rule validate against a specific beats schema, add it to metadata->beats_version')

    return rule
