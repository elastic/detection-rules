# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Kibana cli commands."""
import sys
from pathlib import Path
from typing import Iterable, List, Optional

import click

import kql
from kibana import Signal, RuleResource

from .cli_utils import multi_collection
from .main import root
from .misc import add_params, client_error, kibana_options, get_kibana_client, nested_set
from .rule import downgrade_contents_from_rule, TOMLRuleContents, TOMLRule
from .rule_loader import RuleCollection
from .utils import format_command_options, rulename_to_filename


@root.group('kibana')
@add_params(*kibana_options)
@click.pass_context
def kibana_group(ctx: click.Context, **kibana_kwargs):
    """Commands for integrating with Kibana."""
    ctx.ensure_object(dict)

    # only initialize an kibana client if the subcommand is invoked without help (hacky)
    if sys.argv[-1] in ctx.help_option_names:
        click.echo('Kibana client:')
        click.echo(format_command_options(ctx))

    else:
        ctx.obj['kibana'] = get_kibana_client(**kibana_kwargs)


@kibana_group.command("upload-rule")
@multi_collection
@click.option('--replace-id', '-r', is_flag=True, help='Replace rule IDs with new IDs before export')
@click.pass_context
def upload_rule(ctx, rules: RuleCollection, replace_id):
    """Upload a list of rule .toml files to Kibana."""
    kibana = ctx.obj['kibana']
    api_payloads = []

    for rule in rules:
        try:
            payload = downgrade_contents_from_rule(rule, kibana.version, replace_id=replace_id)
        except ValueError as e:
            client_error(f'{e} in version:{kibana.version}, for rule: {rule.name}', e, ctx=ctx)

        rule = RuleResource(payload)
        api_payloads.append(rule)

    with kibana:
        results = RuleResource.bulk_create_legacy(api_payloads)

    success = []
    errors = []
    for result in results:
        if 'error' in result:
            errors.append(f'{result["rule_id"]} - {result["error"]["message"]}')
        else:
            success.append(result['rule_id'])

    if success:
        click.echo('Successful uploads:\n  - ' + '\n  - '.join(success))
    if errors:
        click.echo('Failed uploads:\n  - ' + '\n  - '.join(errors))

    return results


@kibana_group.command('import-rules')
@multi_collection
@click.option('--overwrite', '-o', is_flag=True, help='Overwrite existing rules')
@click.option('--overwrite-exceptions', '-e', is_flag=True, help='Overwrite exceptions in existing rules')
@click.option('--overwrite-action-connectors', '-a', is_flag=True,
              help='Overwrite action connectors in existing rules')
@click.pass_context
def kibana_import_rules(ctx: click.Context, rules: RuleCollection, overwrite: Optional[bool] = False,
                        overwrite_exceptions: Optional[bool] = False,
                        overwrite_action_connectors: Optional[bool] = False) -> (dict, List[RuleResource]):
    """Import custom rules into Kibana."""
    kibana = ctx.obj['kibana']
    rule_dicts = [r.contents.to_api_format() for r in rules]
    with kibana:
        response, successful_rule_ids, results = RuleResource.import_rules(
            rule_dicts,
            overwrite=overwrite,
            overwrite_exceptions=overwrite_exceptions,
            overwrite_action_connectors=overwrite_action_connectors
        )

    if successful_rule_ids:
        click.echo(f'{len(successful_rule_ids)} rule(s) successfully imported')
        rule_str = '\n - '.join(successful_rule_ids)
        print(f' - {rule_str}')
    if response['errors']:
        click.echo(f'{len(response["errors"])} rule(s) failed to import!')
        for error in response['errors']:
            click.echo(f' - {error["rule_id"]}: ({error["error"]["status_code"]}) {error["error"]["message"]}')

    return response, results


@kibana_group.command('export-rules')
@click.option('--directory', '-d', required=True, type=Path, help='Directory to export rules to')
@click.option('--rule-id', '-r', multiple=True, help='Optional Rule IDs to restrict export to')
@click.option('--skip-errors', '-s', is_flag=True, help='Skip errors when exporting rules')
@click.pass_context
def kibana_export_rules(ctx: click.Context, directory: Path,
                        rule_id: Optional[Iterable[str]] = None, skip_errors: bool = False) -> List[TOMLRule]:
    """Export custom rules from Kibana."""
    kibana = ctx.obj['kibana']
    with kibana:
        results = RuleResource.export_rules(list(rule_id))

    if results:
        directory.mkdir(parents=True, exist_ok=True)

    errors = []
    exported = []
    for rule_resource in results:
        try:
            contents = TOMLRuleContents.from_rule_resource(rule_resource, maturity='production')
            threat = contents.data.get('threat')
            first_tactic = threat[0].tactic.name if threat else ''
            rule_name = rulename_to_filename(contents.data.name, tactic_name=first_tactic)
            rule = TOMLRule(contents=contents, path=directory / f'{rule_name}')
        except Exception as e:
            if skip_errors:
                print(f'- skipping {rule_resource.get("name")} - {type(e).__name__}')
                errors.append(f'- {rule_resource.get("name")} - {e}')
                continue
            raise

        exported.append(rule)

    saved = []
    for rule in exported:
        try:
            rule.save_toml()
        except Exception as e:
            if skip_errors:
                print(f'- skipping {rule.contents.data.name} - {type(e).__name__}')
                errors.append(f'- {rule.contents.data.name} - {e}')
                continue
            raise

        saved.append(rule)

    click.echo(f'{len(results)} rules exported')
    click.echo(f'{len(exported)} rules converted')
    click.echo(f'{len(saved)} saved to {directory}')
    if errors:
        err_file = directory / '_errors.txt'
        err_file.write_text('\n'.join(errors))
        click.echo(f'{len(errors)} errors saved to {err_file}')

    return exported


@kibana_group.command('search-alerts')
@click.argument('query', required=False)
@click.option('--date-range', '-d', type=(str, str), default=('now-7d', 'now'), help='Date range to scope search')
@click.option('--columns', '-c', multiple=True, help='Columns to display in table')
@click.option('--extend', '-e', is_flag=True, help='If columns are specified, extend the original columns')
@click.option('--max-count', '-m', default=100, help='The max number of alerts to return')
@click.pass_context
def search_alerts(ctx, query, date_range, columns, extend, max_count):
    """Search detection engine alerts with KQL."""
    from eql.table import Table
    from .eswrap import MATCH_ALL, add_range_to_dsl

    kibana = ctx.obj['kibana']
    start_time, end_time = date_range
    kql_query = kql.to_dsl(query) if query else MATCH_ALL
    add_range_to_dsl(kql_query['bool'].setdefault('filter', []), start_time, end_time)

    with kibana:
        alerts = [a['_source'] for a in Signal.search({'query': kql_query}, size=max_count)['hits']['hits']]

    # check for events with nested signal fields
    if alerts:
        table_columns = ['host.hostname']

        if 'signal' in alerts[0]:
            table_columns += ['signal.rule.name', 'signal.status', 'signal.original_time']
        elif 'kibana.alert.rule.name' in alerts[0]:
            table_columns += ['kibana.alert.rule.name', 'kibana.alert.status', 'kibana.alert.original_time']
        else:
            table_columns += ['rule.name', '@timestamp']
        if columns:
            columns = list(columns)
            table_columns = table_columns + columns if extend else columns

        # Table requires the data to be nested, but depending on the version, some data uses dotted keys, so
        # they must be nested explicitly
        for alert in alerts:
            for key in table_columns:
                if key in alert:
                    nested_set(alert, key, alert[key])

        click.echo(Table.from_list(table_columns, alerts))
    else:
        click.echo('No alerts detected')
    return alerts
