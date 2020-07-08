# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""CLI commands for detection_rules."""
import glob
import io
import json
import os

import click
import jsonschema
import pytoml
from eql import load_dump

from .misc import LICENSE_HEADER, nested_set
from . import rule_loader
from .packaging import PACKAGE_FILE, Package, manage_versions
from .rule import RULE_TYPE_OPTIONS, Rule
from .rule_formatter import toml_write
from .utils import get_path, clear_caches


RULES_DIR = get_path('rules')


@click.group('detection-rules', context_settings={'help_option_names': ['-h', '--help']})
def root():
    """Commands for detection-rules repository."""


@root.command('create-rule')
@click.argument('path', type=click.Path(dir_okay=False))
@click.option('--config', '-c', type=click.Path(exists=True, dir_okay=False), help='Rule or config file')
@click.option('--required-only', is_flag=True, help='Only prompt for required fields')
@click.option('--rule-type', '-t', type=click.Choice(RULE_TYPE_OPTIONS), help='Type of rule to create')
def create_rule(path, config, required_only, rule_type):
    """Create a detection rule."""
    config = load_dump(config) if config else {}
    try:
        return Rule.build(path, rule_type=rule_type, required_only=required_only, save=True, **config)
    finally:
        rule_loader.reset()


@root.command('load-from-file')
@click.argument('infile', type=click.Path(dir_okay=False, exists=True), nargs=-1, required=False)
@click.option('--directory', '-d', type=click.Path(file_okay=False, exists=True), help='Load files from a directory')
def load_from_file(infile, directory):
    """Load rules from file(s)."""
    if infile:
        for rule_file in infile:
            rule_path = os.path.join(RULES_DIR, os.path.basename(rule_file))
            rule = Rule(rule_path, load_dump(rule_file))
            rule.save(as_rule=True, verbose=True)
    elif directory:
        for rule_file in glob.glob(os.path.join(directory, '**', '*.*'), recursive=True):
            try:
                rule_path = os.path.join(RULES_DIR, os.path.basename(rule_file))
                rule = Rule(rule_path, load_dump(rule_file))
                rule.save(as_rule=True, verbose=True)
            except ValueError:
                click.echo('Unable to load file: {}'.format(rule_file))
    else:
        click.echo('No files specified!')


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
@click.option('--field', type=(str, str), multiple=True,
              help='Use rule-search to retrieve a subset of rules and modify values '
                   '(ex: --field management.ecs_version 1.1.1).\n'
                   'Note this is limited to string fields only. Nested fields should use dot notation.')
@click.pass_context
def mass_update(ctx, query, field):
    """Update multiple rules based on eql results."""
    results = ctx.invoke(search_rules, query=query, verbose=False)
    rules = [rule_loader.get_rule(r['rule_id']) for r in results]

    for rule in rules:
        for key, value in field:
            nested_set(rule.contents, key, value)

        rule.validate(as_rule=True)
        rule.save()

    return ctx.invoke(search_rules, query=query, columns=[k[0].split('.')[-1] for k in field])


@root.command('view-rule')
@click.argument('rule-id', required=False)
@click.option('--rule-file', '-f', type=click.Path(dir_okay=False), help='Optionally view a rule from a specified file')
@click.option('--as-api/--as-rule', default=True, help='Print the rule in final api or rule format')
def view_rule(rule_id, rule_file, as_api):
    """View an internal rule or specified rule file."""
    if rule_id:
        rule = rule_loader.get_rule(rule_id, verbose=False)
    elif rule_file:
        rule = Rule(rule_file, load_dump(rule_file))
    else:
        click.secho('Unknown rule!', fg='red')
        return

    if not rule:
        click.secho('Unknown format!', fg='red')
        return

    click.echo(toml_write(rule.rule_format()) if not as_api else json.dumps(rule.contents, indent=2, sort_keys=True))

    return rule


@root.command('validate-rule')
@click.argument('rule-id', required=False)
@click.option('--rule-name', '-n')
@click.option('--path', '-p', type=click.Path(dir_okay=False))
def validate_rule(rule_id, rule_name, path):
    """Check if a rule staged in rules dir validates against a schema."""
    rule = rule_loader.get_rule(rule_id, rule_name, path, verbose=False)

    if not rule:
        return click.secho('Rule not found!', fg='red')

    try:
        rule.validate(as_rule=True)
    except jsonschema.ValidationError as e:
        click.echo(e)

    click.echo('Rule validation successful')

    return rule


@root.command('license-check')
@click.pass_context
def license_check(ctx):
    """Check that all code files contain a valid license."""

    failed = False

    for path in glob.glob(get_path("**", "*.py"), recursive=True):
        if path.startswith(get_path("env", "")):
            continue

        relative_path = os.path.relpath(path)

        with io.open(path, "rt", encoding="utf-8") as f:
            contents = f.read()

            # skip over shebang lines
            if contents.startswith("#!/"):
                _, _, contents = contents.partition("\n")

            if not contents.lstrip("\r\n").startswith(LICENSE_HEADER):
                if not failed:
                    click.echo("Missing license headers for:", err=True)

                failed = True
                click.echo(relative_path, err=True)

    ctx.exit(int(failed))


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
def search_rules(query, columns, language, verbose=True):
    """Use KQL or EQL to find matching rules."""
    from kql import get_evaluator
    from eql.table import Table
    from eql.build import get_engine
    from eql import parse_query
    from eql.pipes import CountPipe

    flattened_rules = []

    for file_name, rule_doc in rule_loader.load_rule_files().items():
        flat = {"file": os.path.relpath(file_name)}
        flat.update(rule_doc)
        flat.update(rule_doc["metadata"])
        flat.update(rule_doc["rule"])
        attacks = [threat for threat in rule_doc["rule"].get("threat", []) if threat["framework"] == "MITRE ATT&CK"]
        techniques = [t["id"] for threat in attacks for t in threat.get("technique", [])]
        tactics = [threat["tactic"]["name"] for threat in attacks]
        flat.update(techniques=techniques, tactics=tactics)
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

    if columns:
        columns = ",".join(columns).split(",")
    else:
        columns = ["rule_id", "file", "name"]

    table = Table.from_list(columns, filtered)

    if verbose:
        click.echo(table)

    return filtered


@root.command('build-release')
@click.argument('config-file', type=click.Path(exists=True, dir_okay=False), required=False, default=PACKAGE_FILE)
@click.option('--update-version-lock', '-u', is_flag=True,
              help='Save version.lock.json file with updated rule versions in the package')
def build_release(config_file, update_version_lock):
    """Assemble all the rules into Kibana-ready release files."""
    config = load_dump(config_file)['package']
    click.echo('[+] Building package {}'.format(config.get('name')))
    package = Package.from_config(config, update_version_lock=update_version_lock)
    package.save()
    package.get_package_hash(verbose=True)
    click.echo('- {} rules included'.format(len(package.rules)))


@root.command('update-lock-versions')
@click.argument('rule-ids', nargs=-1, required=True)
def update_lock_versions(rule_ids):
    """Update rule hashes in version.lock.json file without bumping version."""
    from .packaging import manage_versions

    if not click.confirm('Are you sure you want to update hashes without a version bump?'):
        return

    rules = [r for r in rule_loader.load_rules(verbose=False).values() if r.id in rule_ids]
    changed, new = manage_versions(rules, exclude_version_update=True, add_new=False, save_changes=True)

    if not changed:
        click.echo('No hashes updated')

    return changed


@root.command('kibana-diff')
@click.option('--rule-id', '-r', multiple=True, help='Optionally specify rule ID')
@click.option('--branch', '-b', default='master', help='Specify the kibana branch to diff against')
def kibana_diff(rule_id, branch):
    """Diff rules against their version represented in kibana if exists."""
    from .misc import get_kibana_rules

    if rule_id:
        rules = [r for r in rule_loader.load_rules(verbose=False).values() if r.id in rule_id]
    else:
        rules = [r for r in rule_loader.load_rules(verbose=False).values() if r.metadata['maturity'] == 'production']

    # add versions to the rules
    manage_versions(rules, verbose=False)

    rule_paths = [os.path.basename(r.path) for r in rules]
    try:
        original_gh_rules = get_kibana_rules(*rule_paths, branch=branch).values()
    except ValueError as e:
        click.secho(e.args[0], fg='red', err=True)
        return

    gh_rule_versions = {r['rule_id']: r.pop('version') for r in original_gh_rules}
    rule_versions = {r.id: r.contents.pop('version') for r in rules}

    gh_rules = {r['rule_id']: Rule('_', r) for r in original_gh_rules}

    rule_ids = [r.id for r in rules]
    gh_rule_ids = [r.id for r in gh_rules.values()]

    missing_rules = [r for r in gh_rules.values() if r.id in list(set(gh_rule_ids).difference(set(rule_ids)))]

    diff = {
        'missing_from_kibana': [],
        'diff': [],
        'missing_from_rules': ['{} - {}'.format(r.id, r.name) for r in missing_rules]
    }
    for rule in rules:
        if rule.id not in gh_rule_ids:
            diff['missing_from_kibana'].append('{} - {}'.format(rule.id, rule.name))
            continue

        gh_rule = gh_rules[rule.id]

        if rule.get_hash() != gh_rule.get_hash():
            diff['diff'].append('versions - repo: {}, kibana: {} -> {} - {}'.format(
                rule_versions[rule.id], gh_rule_versions[rule.id], rule.id, rule.name))

    click.echo(json.dumps(diff, indent=2, sort_keys=True))


@root.command("test")
@click.pass_context
def test_rules(ctx):
    """Run unit tests over all of the rules."""
    import pytest

    clear_caches()
    ctx.exit(pytest.main(["-v"]))
