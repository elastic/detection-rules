# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Kibana cli commands."""
import sys
from typing import List, Optional, Tuple

import click


import kql
from kibana import Signal, RuleResource
from .cli_utils import multi_collection
from .main import root
from .misc import add_params, client_error, kibana_options, get_kibana_client, nested_set
from .rule import downgrade_contents_from_rule
from .utils import format_command_options


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
def upload_rule(ctx, rules, replace_id):
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
@click.argument('rules', nargs=-1, required=True)
@click.option('--overwrite', '-o', is_flag=True, help='Overwrite existing rules')
@click.option('--overwrite-exceptions', '-e', is_flag=True, help='Overwrite exceptions in existing rules')
@click.option('--overwrite-action-connectors', '-a', is_flag=True,
              help='Overwrite action connectors in existing rules')
def kibana_import_rules(ctx: click.Context, rules: Tuple[dict], overwrite: Optional[bool] = False,
                        overwrite_exceptions: Optional[bool] = False,
                        overwrite_action_connectors: Optional[bool] = False) -> (dict, List[RuleResource]):
    """Import rules into Kibana."""
    kibana = ctx.obj['kibana']
    with kibana:
        response, results = RuleResource.import_rules(list(rules), overwrite=overwrite,
                                                      overwrite_exceptions=overwrite_exceptions,
                                                      overwrite_action_connectors=overwrite_action_connectors)

    return response, results


@kibana_group.command('export-rules')
@click.option('--rule-id', '-r', multiple=True, help='Optional Rule IDs to restrict export to')
def kibana_export_rules(ctx: click.Context, rule_id: Optional[Tuple[str]] = None) -> List[RuleResource]:
    """Export rules from Kibana."""
    kibana = ctx.obj['kibana']
    with kibana:
        results = RuleResource.export_rules(list(rule_id))

    return results


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
