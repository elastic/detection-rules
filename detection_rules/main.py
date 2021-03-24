# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""CLI commands for detection_rules."""
import dataclasses
import glob
import json
import os
import re
import time
from pathlib import Path
from typing import Dict
from uuid import uuid4

import click

from . import rule_loader
from .cli_utils import rule_prompt
from .misc import client_error, nested_set, parse_config
from .rule import TOMLRule
from .rule_formatter import toml_write
from .rule_loader import RuleCollection
from .schemas import CurrentSchema, available_versions
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
        return rule_prompt(path, rule_type=rule_type, required_only=required_only, save=True, **contents)
    finally:
        rule_loader.reset()


@root.command('generate-rules-index')
@click.option('--query', '-q', help='Optional KQL query to limit to specific rules')
@click.option('--overwrite', is_flag=True, help='Overwrite files in an existing folder')
@click.pass_context
def generate_rules_index(ctx: click.Context, query, overwrite, save_files=True):
    """Generate enriched indexes of rules, based on a KQL search, for indexing/importing into elasticsearch/kibana."""
    from .packaging import load_current_package_version, Package

    if query:
        rule_paths = [r['file'] for r in ctx.invoke(search_rules, query=query, verbose=False)]
        rules = RuleCollection()
        rules.load_files(Path(p) for p in rule_paths)
    else:
        rules = RuleCollection.default()

    rule_count = len(rules)
    package = Package(rules, load_current_package_version(), verbose=False)
    package_hash = package.get_package_hash()
    bulk_upload_docs, importable_rules_docs = package.create_bulk_index_body()

    if save_files:
        path = Path(get_path('enriched-rule-indexes', package_hash))
        path.mkdir(parents=True, exist_ok=overwrite)
        bulk_upload_docs.dump(path.joinpath('enriched-rules-index-uploadable.ndjson'), sort_keys=True)
        importable_rules_docs.dump(path.joinpath('enriched-rules-index-importable.ndjson'), sort_keys=True)

        click.echo(f'files saved to: {path}')

    click.echo(f'{rule_count} rules included')

    return bulk_upload_docs, importable_rules_docs


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
        rule_prompt(rule_path, required_only=True, save=True, verbose=True, **contents)


@root.command('toml-lint')
@click.option('--rule-file', '-f', type=click.Path('r'), help='Optionally specify a specific rule file only')
def toml_lint(rule_file):
    """Cleanup files with some simple toml formatting."""
    if rule_file:
        rules = list(rule_loader.load_rules(rule_loader.load_rule_files(paths=[rule_file])).values())
    else:
        rules = list(rule_loader.load_rules().values())

    # removed unneeded defaults
    # TODO: we used to remove "unneeded" defaults, but this is a potentially tricky thing.
    #       we need to figure out if a default is Kibana-imposed or detection-rules imposed.
    #       ideally, we can explicitly mention default in TOML if desired and have a concept
    #       of build-time defaults, so that defaults are filled in as late as possible

    # re-save the rules to force TOML reformatting
    for rule in rules:
        rule.save_toml()

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
    rules = RuleCollection().default()
    results = ctx.invoke(search_rules, query=query, language=language, verbose=False)
    matching_ids = set(r["rule_id"] for r in results)
    rules = rules.filter(lambda r: r.id in matching_ids)

    for rule in rules:
        for key, value in field:
            nested_set(rule.metadata if metadata else rule.contents, key, value)

        rule.validate(as_rule=True)
        rule.save(as_rule=True)

    return ctx.invoke(search_rules, query=query, language=language,
                      columns=['rule_id', 'name'] + [k[0].split('.')[-1] for k in field])


@root.command('view-rule')
@click.argument('rule-file')
@click.option('--api-format/--rule-format', default=True, help='Print the rule in final api or rule format')
@click.pass_context
def view_rule(ctx, rule_file, api_format):
    """View an internal rule or specified rule file."""
    rule = RuleCollection().load_file(rule_file)

    if api_format:
        click.echo(json.dumps(rule.contents.to_api_format(), indent=2, sort_keys=True))
    else:
        click.echo(toml_write(rule.contents.to_dict()))


@root.command('export-rules')
@click.argument('rule-id', nargs=-1, required=False)
@click.option('--rule-file', '-f', multiple=True, type=click.Path(dir_okay=False), help='Export specified rule files')
@click.option('--directory', '-d', multiple=True, type=click.Path(file_okay=False),
              help='Recursively export rules from a directory')
@click.option('--outfile', '-o', default=get_path('exports', f'{time.strftime("%Y%m%dT%H%M%SL")}.ndjson'),
              type=click.Path(dir_okay=False), help='Name of file for exported rules')
@click.option('--replace-id', '-r', is_flag=True, help='Replace rule IDs with new IDs before export')
@click.option('--stack-version', type=click.Choice(available_versions),
              help='Downgrade a rule version to be compatible with older instances of Kibana')
@click.option('--skip-unsupported', '-s', is_flag=True,
              help='If `--stack-version` is passed, skip rule types which are unsupported '
                   '(an error will be raised otherwise)')
def export_rules(rule_id, rule_file, directory, outfile, replace_id, stack_version, skip_unsupported):
    """Export rule(s) into an importable ndjson file."""
    from .packaging import Package

    if not (rule_id or rule_file or directory):
        client_error('Required: at least one of --rule-id, --rule-file, or --directory')

    rules = RuleCollection()

    if rule_id:
        rule_id = set(rule_id)
        rules = RuleCollection.default().filter(lambda r: r.id in rule_id)
        found_ids = {rule.id for rule in rules}
        missing = rule_id.difference(found_ids)

        if missing:
            client_error(f'Unknown rules for rule IDs: {", ".join(missing)}')

    if rule_file:
        rules.load_files(Path(path) for path in rule_file)

    for directory in directory:
        rules.load_directory(Path(directory))

    assert len(rules) > 0, "No rules found"

    if replace_id:
        # if we need to replace the id, take each rule object and create a copy
        # of it, with only the rule_id field changed
        old_rules = rules
        rules = RuleCollection()

        for rule in old_rules:
            new_data = dataclasses.replace(rule.contents.data, rule_id=str(uuid4()))
            new_contents = dataclasses.replace(rule.contents, data=new_data)
            rules.add_rule(TOMLRule(contents=new_contents))

    Path(outfile).parent.mkdir(exist_ok=True)
    package = Package(rules, '_', verbose=False)
    package.export(outfile, downgrade_version=stack_version, skip_unsupported=skip_unsupported)
    return package.rules


@root.command('validate-rule')
@click.argument('path')
@click.pass_context
def validate_rule(ctx, path):
    """Check if a rule staged in rules dir validates against a schema."""
    rule = RuleCollection().load_file(Path(path))
    click.echo('Rule validation successful')
    return rule


@root.command('validate-all')
def validate_all(fail):
    """Check if all rules validates against a schema."""
    RuleCollection.default()
    click.echo('Rule validation successful')


@root.command('rule-search')
@click.argument('query', required=False)
@click.option('--columns', '-c', multiple=True, help='Specify columns to add the table')
@click.option('--language', type=click.Choice(["eql", "kql"]), default="kql")
@click.option('--count', is_flag=True, help='Return a count rather than table')
def search_rules(query, columns, language, count, verbose=True, rules: Dict[str, dict] = None, pager=False):
    """Use KQL or EQL to find matching rules."""
    from kql import get_evaluator
    from eql.table import Table
    from eql.build import get_engine
    from eql import parse_query
    from eql.pipes import CountPipe

    flattened_rules = []
    rules = rules or rule_loader.load_rule_files(verbose=verbose)

    for file_name, rule_doc in rules.items():
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
                    unique_fields=TOMLRule.get_unique_query_fields(rule_doc['rule']))
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
        click.echo_via_pager(table) if pager else click.echo(table)

    return filtered


@root.command("test")
@click.pass_context
def test_rules(ctx):
    """Run unit tests over all of the rules."""
    import pytest

    clear_caches()
    ctx.exit(pytest.main(["-v"]))
