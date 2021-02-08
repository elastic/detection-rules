# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""CLI commands for detection_rules."""
import glob
import json
import os
import re

import click
import jsonschema
import pytoml

from . import rule_loader
from .misc import client_error, nested_set, parse_config
from .rule import Rule
from .rule_formatter import toml_write
from .schemas import CurrentSchema
from .utils import get_path, clear_caches, load_rule_contents


RULES_DIR = get_path('rules')


@click.group('detection-rules', context_settings={'help_option_names': ['-h', '--help']})
@click.option('--debug/--no-debug', '-D/-N', is_flag=True, default=None,
              help='Print full exception stacktrace on errors')
@click.pass_context
def root(ctx, debug):
    """Commands for detection-rules repository."""
    debug = debug if debug is not None else parse_config().get('debug')
    ctx.obj = {'debug': debug}
    if debug:
        click.secho('DEBUG MODE ENABLED', fg='yellow')


@root.command('create-rule')
@click.argument('path', type=click.Path(dir_okay=False))
@click.option('--config', '-c', type=click.Path(exists=True, dir_okay=False), help='Rule or config file')
@click.option('--required-only', is_flag=True, help='Only prompt for required fields')
@click.option('--rule-type', '-t', type=click.Choice(CurrentSchema.RULE_TYPES), help='Type of rule to create')
def create_rule(path, config, required_only, rule_type):
    """Create a detection rule."""
    contents = load_rule_contents(config, single_only=True)[0] if config else {}
    try:
        return Rule.build(path, rule_type=rule_type, required_only=required_only, save=True, **contents)
    finally:
        rule_loader.reset()


@root.command('import-rules')
@click.argument('infile', type=click.Path(dir_okay=False, exists=True), nargs=-1, required=False)
@click.option('--directory', '-d', type=click.Path(file_okay=False, exists=True), help='Load files from a directory')
def import_rules(infile, directory):
    """Import rules from json, toml, or Kibana exported rule file(s)."""
    rule_files = glob.glob(os.path.join(directory, '**', '*.*'), recursive=True) if directory else []
    rule_files = sorted(set(rule_files + list(infile)))

    rule_contents = []
    for rule_file in rule_files:
        rule_contents.extend(load_rule_contents(rule_file))

    if not rule_contents:
        click.echo('Must specify at least one file!')

    def name_to_filename(name):
        return re.sub(r'[^_a-z0-9]+', '_', name.strip().lower()).strip('_') + '.toml'

    for contents in rule_contents:
        base_path = contents.get('name') or contents.get('rule', {}).get('name')
        base_path = name_to_filename(base_path) if base_path else base_path
        rule_path = os.path.join(RULES_DIR, base_path) if base_path else None
        Rule.build(rule_path, required_only=True, save=True, verbose=True, **contents)


@root.command('toml-lint')
@click.option('--rule-file', '-f', type=click.File('r'), help='Optionally specify a specific rule file only')
def toml_lint(rule_file):
    """Cleanup files with some simple toml formatting."""
    if rule_file:
        contents = pytoml.load(rule_file)
        rule = Rule(path=rule_file.name, contents=contents)

        # removed unneeded defaults
        for field in rule_loader.find_unneeded_defaults(rule):
            rule.contents.pop(field, None)

        rule.save(as_rule=True)
    else:
        for rule in rule_loader.load_rules().values():

            # removed unneeded defaults
            for field in rule_loader.find_unneeded_defaults(rule):
                rule.contents.pop(field, None)

            rule.save(as_rule=True)

    rule_loader.reset()
    click.echo('Toml file linting complete')


@root.command('mass-update')
@click.argument('query')
@click.option('--metadata', '-m', is_flag=True, help='Make an update to the rule metadata rather than contents.')
@click.option('--language', type=click.Choice(["eql", "kql"]), default="kql")
@click.option('--field', type=(str, str), multiple=True,
              help='Use rule-search to retrieve a subset of rules and modify values '
                   '(ex: --field management.ecs_version 1.1.1).\n'
                   'Note this is limited to string fields only. Nested fields should use dot notation.')
@click.pass_context
def mass_update(ctx, query, metadata, language, field):
    """Update multiple rules based on eql results."""
    results = ctx.invoke(search_rules, query=query, language=language, verbose=False)
    rules = [rule_loader.get_rule(r['rule_id'], verbose=False) for r in results]

    for rule in rules:
        for key, value in field:
            nested_set(rule.metadata if metadata else rule.contents, key, value)

        rule.validate(as_rule=True)
        rule.save(as_rule=True)

    return ctx.invoke(search_rules, query=query, language=language,
                      columns=['rule_id', 'name'] + [k[0].split('.')[-1] for k in field])


@root.command('view-rule')
@click.argument('rule-id', required=False)
@click.option('--rule-file', '-f', type=click.Path(dir_okay=False), help='Optionally view a rule from a specified file')
@click.option('--api-format/--rule-format', default=True, help='Print the rule in final api or rule format')
@click.pass_context
def view_rule(ctx, rule_id, rule_file, api_format):
    """View an internal rule or specified rule file."""
    rule = None

    if rule_id:
        rule = rule_loader.get_rule(rule_id, verbose=False)
    elif rule_file:
        contents = {k: v for k, v in load_rule_contents(rule_file, single_only=True)[0].items() if v}

        try:
            rule = Rule(rule_file, contents)
        except jsonschema.ValidationError as e:
            client_error(f'Rule: {rule_id or os.path.basename(rule_file)} failed validation', e, ctx=ctx)
    else:
        client_error('Unknown rule!')

    if not rule:
        client_error('Unknown format!')

    click.echo(toml_write(rule.rule_format()) if not api_format else
               json.dumps(rule.get_payload(), indent=2, sort_keys=True))

    return rule


@root.command('validate-rule')
@click.argument('rule-id', required=False)
@click.option('--rule-name', '-n')
@click.option('--path', '-p', type=click.Path(dir_okay=False))
@click.pass_context
def validate_rule(ctx, rule_id, rule_name, path):
    """Check if a rule staged in rules dir validates against a schema."""
    try:
        rule = rule_loader.get_rule(rule_id, rule_name, path, verbose=False)
        if not rule:
            client_error('Rule not found!')

        rule.validate(as_rule=True)
        click.echo('Rule validation successful')
        return rule
    except jsonschema.ValidationError as e:
        client_error(e.args[0], e, ctx=ctx)


@root.command('validate-all')
@click.option('--fail/--no-fail', default=True, help='Fail on first failure or process through all printing errors.')
def validate_all(fail):
    """Check if all rules validates against a schema."""
    rule_loader.load_rules(verbose=True, error=fail)
    click.echo('Rule validation successful')


@root.command('rule-search')
@click.argument('query', required=False)
@click.option('--columns', '-c', multiple=True, help='Specify columns to add the table')
@click.option('--language', type=click.Choice(["eql", "kql"]), default="kql")
@click.option('--count', is_flag=True, help='Return a count rather than table')
def search_rules(query, columns, language, count, verbose=True):
    """Use KQL or EQL to find matching rules."""
    from kql import get_evaluator
    from eql.table import Table
    from eql.build import get_engine
    from eql import parse_query
    from eql.pipes import CountPipe

    flattened_rules = []

    for file_name, rule_doc in rule_loader.load_rule_files(verbose=verbose).items():
        flat = {"file": os.path.relpath(file_name)}
        flat.update(rule_doc)
        flat.update(rule_doc["metadata"])
        flat.update(rule_doc["rule"])

        tactic_names = []
        technique_ids = []
        subtechnique_ids = []

        for entry in rule_doc['rule'].get('threat', []):
            if entry["framework"] != "MITRE ATT&CK":
                continue

            techniques = entry.get('technique', [])
            tactic_names.append(entry['tactic']['name'])
            technique_ids.extend([t['id'] for t in techniques])
            subtechnique_ids.extend([st['id'] for t in techniques for st in t.get('subtechnique', [])])

        flat.update(techniques=technique_ids, tactics=tactic_names, subtechniques=subtechnique_ids,
                    unique_fields=Rule.get_unique_query_fields(rule_doc['rule']))
        flattened_rules.append(flat)

    flattened_rules.sort(key=lambda dct: dct["name"])

    filtered = []
    if language == "kql":
        evaluator = get_evaluator(query) if query else lambda x: True
        filtered = list(filter(evaluator, flattened_rules))
    elif language == "eql":
        parsed = parse_query(query, implied_any=True, implied_base=True)
        evaluator = get_engine(parsed)
        filtered = [result.events[0].data for result in evaluator(flattened_rules)]

        if not columns and any(isinstance(pipe, CountPipe) for pipe in parsed.pipes):
            columns = ["key", "count", "percent"]

    if count:
        click.echo(f'{len(filtered)} rules')
        return filtered

    if columns:
        columns = ",".join(columns).split(",")
    else:
        columns = ["rule_id", "file", "name"]

    table = Table.from_list(columns, filtered)

    if verbose:
        click.echo(table)

    return filtered


@root.command("test")
@click.pass_context
def test_rules(ctx):
    """Run unit tests over all of the rules."""
    import pytest

    clear_caches()
    ctx.exit(pytest.main(["-v"]))
