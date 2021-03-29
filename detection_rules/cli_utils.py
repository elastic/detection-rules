# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import copy
import datetime
import os
from pathlib import Path

import click

import kql
from . import ecs
from .attack import matrix, tactics, build_threat_map_entry
from .rule import TOMLRule, TOMLRuleContents
from .schemas import CurrentSchema
from .utils import clear_caches, get_path

RULES_DIR = get_path("rules")


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
        click.prompt('Rule type', type=click.Choice(CurrentSchema.RULE_TYPES))

    schema = CurrentSchema.get_schema(role=rule_type)
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
