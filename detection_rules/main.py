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
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional
from uuid import uuid4

import click

from .cli_utils import rule_prompt, multi_collection
from .misc import add_client, client_error, nested_set, parse_config
from .rule import TOMLRule, TOMLRuleContents
from .rule_formatter import toml_write
from .rule_loader import RuleCollection
from .schemas import all_versions, definitions
from .utils import get_path, get_etc_path, clear_caches, load_dump, load_rule_contents

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
@click.argument('path', type=Path)
@click.option('--config', '-c', type=click.Path(exists=True, dir_okay=False), help='Rule or config file')
@click.option('--required-only', is_flag=True, help='Only prompt for required fields')
@click.option('--rule-type', '-t', type=click.Choice(sorted(TOMLRuleContents.all_rule_types())),
              help='Type of rule to create')
def create_rule(path, config, required_only, rule_type):
    """Create a detection rule."""
    contents = load_rule_contents(config, single_only=True)[0] if config else {}
    return rule_prompt(path, rule_type=rule_type, required_only=required_only, save=True, **contents)


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
    package = Package(rules, name=load_current_package_version(), verbose=False)
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
@click.argument('input-file', type=click.Path(dir_okay=False, exists=True), nargs=-1, required=False)
@click.option('--directory', '-d', type=click.Path(file_okay=False, exists=True), help='Load files from a directory')
def import_rules(input_file, directory):
    """Import rules from json, toml, or Kibana exported rule file(s)."""
    rule_files = glob.glob(os.path.join(directory, '**', '*.*'), recursive=True) if directory else []
    rule_files = sorted(set(rule_files + list(input_file)))

    rule_contents = []
    for rule_file in rule_files:
        rule_contents.extend(load_rule_contents(Path(rule_file)))

    if not rule_contents:
        click.echo('Must specify at least one file!')

    def name_to_filename(name):
        return re.sub(r'[^_a-z0-9]+', '_', name.strip().lower()).strip('_') + '.toml'

    for contents in rule_contents:
        base_path = contents.get('name') or contents.get('rule', {}).get('name')
        base_path = name_to_filename(base_path) if base_path else base_path
        rule_path = os.path.join(RULES_DIR, base_path) if base_path else None
        rule_prompt(rule_path, required_only=True, save=True, verbose=True, additional_required=['index'], **contents)


@root.command('toml-lint')
@click.option('--rule-file', '-f', multiple=True, type=click.Path(exists=True),
              help='Specify one or more rule files.')
def toml_lint(rule_file):
    """Cleanup files with some simple toml formatting."""
    if rule_file:
        rules = RuleCollection()
        rules.load_files(Path(p) for p in rule_file)
    else:
        rules = RuleCollection.default()

    # re-save the rules to force TOML reformatting
    for rule in rules:
        rule.save_toml()

    click.echo('TOML file linting complete')


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
@click.argument('rule-file', type=Path)
@click.option('--api-format/--rule-format', default=True, help='Print the rule in final api or rule format')
@click.pass_context
def view_rule(ctx, rule_file, api_format):
    """View an internal rule or specified rule file."""
    rule = RuleCollection().load_file(rule_file)

    if api_format:
        click.echo(json.dumps(rule.contents.to_api_format(), indent=2, sort_keys=True))
    else:
        click.echo(toml_write(rule.contents.to_dict()))

    return rule


def _export_rules(rules: RuleCollection, outfile: Path, downgrade_version: Optional[definitions.SemVer] = None,
                  verbose=True, skip_unsupported=False):
    """Export rules into a consolidated ndjson file."""
    from .rule import downgrade_contents_from_rule

    outfile = outfile.with_suffix('.ndjson')
    unsupported = []

    if downgrade_version:
        if skip_unsupported:
            output_lines = []

            for rule in rules:
                try:
                    output_lines.append(json.dumps(downgrade_contents_from_rule(rule, downgrade_version),
                                                   sort_keys=True))
                except ValueError as e:
                    unsupported.append(f'{e}: {rule.id} - {rule.name}')
                    continue

        else:
            output_lines = [json.dumps(downgrade_contents_from_rule(r, downgrade_version), sort_keys=True)
                            for r in rules]
    else:
        output_lines = [json.dumps(r.contents.to_api_format(), sort_keys=True) for r in rules]

    outfile.write_text('\n'.join(output_lines) + '\n')

    if verbose:
        click.echo(f'Exported {len(rules) - len(unsupported)} rules into {outfile}')

        if skip_unsupported and unsupported:
            unsupported_str = '\n- '.join(unsupported)
            click.echo(f'Skipped {len(unsupported)} unsupported rules: \n- {unsupported_str}')


@root.command('export-rules')
@multi_collection
@click.option('--outfile', '-o', default=Path(get_path('exports', f'{time.strftime("%Y%m%dT%H%M%SL")}.ndjson')),
              type=Path, help='Name of file for exported rules')
@click.option('--replace-id', '-r', is_flag=True, help='Replace rule IDs with new IDs before export')
@click.option('--stack-version', type=click.Choice(all_versions()),
              help='Downgrade a rule version to be compatible with older instances of Kibana')
@click.option('--skip-unsupported', '-s', is_flag=True,
              help='If `--stack-version` is passed, skip rule types which are unsupported '
                   '(an error will be raised otherwise)')
def export_rules(rules, outfile: Path, replace_id, stack_version, skip_unsupported) -> RuleCollection:
    """Export rule(s) into an importable ndjson file."""
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

    outfile.parent.mkdir(exist_ok=True)
    _export_rules(rules=rules, outfile=outfile, downgrade_version=stack_version,
                  skip_unsupported=skip_unsupported)

    return rules


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
def search_rules(query, columns, language, count, verbose=True, rules: Dict[str, TOMLRule] = None, pager=False):
    """Use KQL or EQL to find matching rules."""
    from kql import get_evaluator
    from eql.table import Table
    from eql.build import get_engine
    from eql import parse_query
    from eql.pipes import CountPipe
    from .rule import get_unique_query_fields

    flattened_rules = []
    rules = rules or {str(rule.path): rule for rule in RuleCollection.default()}

    for file_name, rule in rules.items():
        flat: dict = {"file": os.path.relpath(file_name)}
        flat.update(rule.contents.to_dict())
        flat.update(flat["metadata"])
        flat.update(flat["rule"])

        tactic_names = []
        technique_ids = []
        subtechnique_ids = []

        for entry in flat['rule'].get('threat', []):
            if entry["framework"] != "MITRE ATT&CK":
                continue

            techniques = entry.get('technique', [])
            tactic_names.append(entry['tactic']['name'])
            technique_ids.extend([t['id'] for t in techniques])
            subtechnique_ids.extend([st['id'] for t in techniques for st in t.get('subtechnique', [])])

        flat.update(techniques=technique_ids, tactics=tactic_names, subtechniques=subtechnique_ids,
                    unique_fields=get_unique_query_fields(rule))
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


@root.group('typosquat')
def typosquat_group():
    """Commands for generating typosquat detections."""


@typosquat_group.command('create-dnstwist-index')
@click.argument('input-file', type=click.Path(exists=True, dir_okay=False), required=True)
@click.pass_context
@add_client('elasticsearch', add_func_arg=False)
def create_dnstwist_index(ctx: click.Context, input_file: click.Path):
    """Create a dnstwist index in Elasticsearch to work with a threat match rule."""
    from elasticsearch import Elasticsearch

    es_client: Elasticsearch = ctx.obj['es']

    click.echo(f'Attempting to load dnstwist data from {input_file}')
    dnstwist_data: dict = load_dump(input_file)
    click.echo(f'{len(dnstwist_data)} records loaded')

    original_domain = next(r['domain-name'] for r in dnstwist_data if r.get('fuzzer', '') == 'original*')
    click.echo(f'Original domain name identified: {original_domain}')

    domain = original_domain.split('.')[0]
    domain_index = f'dnstwist-{domain}'
    # If index already exists, prompt user to confirm if they want to overwrite
    if es_client.indices.exists(index=domain_index):
        if click.confirm(
                f"dnstwist index: {domain_index} already exists for {original_domain}. Do you want to overwrite?",
                abort=True):
            es_client.indices.delete(index=domain_index)

    fields = [
        "dns-a",
        "dns-aaaa",
        "dns-mx",
        "dns-ns",
        "banner-http",
        "fuzzer",
        "original-domain",
        "dns.question.registered_domain"
    ]
    timestamp_field = "@timestamp"
    mappings = {"mappings": {"properties": {f: {"type": "keyword"} for f in fields}}}
    mappings["mappings"]["properties"][timestamp_field] = {"type": "date"}

    es_client.indices.create(index=domain_index, body=mappings)

    # handle dns.question.registered_domain separately
    fields.pop()
    es_updates = []
    now = datetime.utcnow()

    for item in dnstwist_data:
        if item['fuzzer'] == 'original*':
            continue

        record = item.copy()
        record.setdefault('dns', {}).setdefault('question', {}).setdefault('registered_domain', item.get('domain-name'))

        for field in fields:
            record.setdefault(field, None)

        record['@timestamp'] = now

        es_updates.extend([{'create': {'_index': domain_index}}, record])

    click.echo(f'Indexing data for domain {original_domain}')

    results = es_client.bulk(body=es_updates)
    if results['errors']:
        error = {r['create']['result'] for r in results['items'] if r['create']['status'] != 201}
        client_error(f'Errors occurred during indexing:\n{error}')

    click.echo(f'{len(results["items"])} watchlist domains added to index')
    click.echo('Run `prep-rule` and import to Kibana to create alerts on this index')


@typosquat_group.command('prep-rule')
@click.argument('author')
def prep_rule(author: str):
    """Prep the detection threat match rule for dnstwist data with a rule_id and author."""
    rule_template_file = Path(get_etc_path('rule_template_typosquatting_domain.json'))
    template_rule = json.loads(rule_template_file.read_text())
    template_rule.update(author=[author], rule_id=str(uuid4()))
    updated_rule = Path(get_path('rule_typosquatting_domain.ndjson'))
    updated_rule.write_text(json.dumps(template_rule, sort_keys=True))
    click.echo(f'Rule saved to: {updated_rule}. Import this to Kibana to create alerts on all dnstwist-* indexes')
    click.echo('Note: you only need to import and enable this rule one time for all dnstwist-* indexes')
