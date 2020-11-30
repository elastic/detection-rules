# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Kibana cli commands."""
import click
import kql
from kibana import Kibana, Signal, RuleResource
from requests.exceptions import HTTPError

from .main import root
from .misc import add_params, client_error, kibana_options
from .rule_loader import load_rule_files, load_rules
from .utils import format_command_options


def get_kibana_client(cloud_id, kibana_url, kibana_user, kibana_password, **kwargs):
    """Get an authenticated Kibana client."""
    if not (cloud_id or kibana_url):
        client_error("Missing required --cloud-id or --kibana-url")

    # don't prompt for these until there's a cloud id or Kibana URL
    kibana_user = kibana_user or click.prompt("kibana_user")
    kibana_password = kibana_password or click.prompt("kibana_password", hide_input=True)

    with Kibana(cloud_id=cloud_id, kibana_url=kibana_url, **kwargs) as kibana:
        kibana.login(kibana_user, kibana_password)
        return kibana


@root.group('kibana')
@add_params(*kibana_options)
@click.pass_context
def kibana_group(ctx: click.Context, **kibana_kwargs):
    """Commands for integrating with Kibana."""
    ctx.ensure_object(dict)

    # only initialize an kibana client if the subcommand is invoked without help (hacky)
    if click.get_os_args()[-1] in ctx.help_option_names:
        click.echo('Kibana client:')
        click.echo(format_command_options(ctx))

    else:
        ctx.obj['kibana'] = get_kibana_client(**kibana_kwargs)


@kibana_group.command("upload-rule")
@click.option('--preserve-id', is_flag=True, help='Preserve the rule_id from toml file as rule id')
@click.option('--force', is_flag=True, help='Force the usage of --preserver-id; a.k.a do not get a confirm pop-up')
@click.argument("toml-files", nargs=-1, required=True)
@click.pass_context
def upload_rule(ctx, preserve_id, force, toml_files):
    """Upload a list of rule .toml files to Kibana."""
    from uuid import uuid4
    from .packaging import manage_versions
    from .schemas import downgrade

    kibana = ctx.obj['kibana']
    file_lookup = load_rule_files(paths=toml_files)
    rules = list(load_rules(file_lookup=file_lookup).values())

    # assign the versions from etc/versions.lock.json
    # rules that have changed in hash get incremented, others stay as-is.
    # rules that aren't in the lookup default to version 1
    manage_versions(rules, verbose=False)

    api_payloads = []

    for rule in rules:
        payload = rule.contents.copy()
        meta = payload.setdefault("meta", {})
        meta["original"] = dict(id=rule.id, **rule.metadata)

        # Determine the rule id to use.
        # Github issue 612
        if preserve_id and not force:
            with kibana:
                # determine if the rule already exists
                try:
                    resp = kibana.request(
                        method="GET",
                        uri="/api/detection_engine/rules",
                        params={
                            "rule_id": rule.id
                        }
                    )
                except HTTPError:
                    # HTTPError is raised if the rule does not exist
                    payload["rule_id"] = rule.id
                else:
                    # Rule exists, asking user to overwrite or not
                    print("The rule {} already exists with the given rule id".format(resp["name"]))
                    overwrite = input("Overwrite existing rule: [y/n]")
                    if overwrite in ["y", "Y"]:
                        payload["rule_id"] = rule.id
                    else:
                        payload["rule_id"] = str(uuid4())
                        print("New rule id = {}".format(payload["rule_id"]))
        elif preserve_id and force:
            payload["rule_id"] = rule.id
        else:
            payload["rule_id"] = str(uuid4())
        payload = downgrade(payload, kibana.version)
        rule = RuleResource(payload)
        api_payloads.append(rule)

    with kibana:
        rules = RuleResource.bulk_create(api_payloads)
        click.echo(f"Successfully uploaded {len(rules)} rules")


@kibana_group.command('search-alerts')
@click.argument('query', required=False)
@click.option('--date-range', '-d', type=(str, str), default=('now-7d', 'now'), help='Date range to scope search')
@click.option('--columns', '-c', multiple=True, help='Columns to display in table')
@click.option('--extend', '-e', is_flag=True, help='If columns are specified, extend the original columns')
@click.pass_context
def search_alerts(ctx, query, date_range, columns, extend):
    """Search detection engine alerts with KQL."""
    from eql.table import Table
    from .eswrap import MATCH_ALL, add_range_to_dsl

    kibana = ctx.obj['kibana']
    start_time, end_time = date_range
    kql_query = kql.to_dsl(query) if query else MATCH_ALL
    add_range_to_dsl(kql_query['bool'].setdefault('filter', []), start_time, end_time)

    with kibana:
        alerts = [a['_source'] for a in Signal.search({'query': kql_query})['hits']['hits']]

    table_columns = ['host.hostname', 'signal.rule.name', 'signal.status', 'signal.original_time']
    if columns:
        columns = list(columns)
        table_columns = table_columns + columns if extend else columns
    click.echo(Table.from_list(table_columns, alerts))
    return alerts
