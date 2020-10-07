# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Kibana cli commands."""
import click
from kibana import Kibana, RuleResource

from .main import root
from .misc import client_error, getdefault
from .rule_loader import load_rule_files, load_rules
from .utils import format_command_options


@root.group('kibana')
@click.option('--kibana-url', '-k', default=getdefault('kibana_url'))
@click.option('--cloud-id', default=getdefault('cloud_id'))
@click.option('--kibana-user', '-u', default=getdefault('kibana_user'))
@click.option('--kibana-password', '-p', default=getdefault("kibana_password"))
@click.pass_context
def kibana_group(ctx: click.Context, **kibana_kwargs):
    """Commands for integrating with Kibana."""
    ctx.ensure_object(dict)

    # only initialize an kibana client if the subcommand is invoked without help (hacky)
    if click.get_os_args()[-1] in ctx.help_option_names:
        click.echo('Kibana client:')
        click.echo(format_command_options(ctx))

    else:
        if not kibana_kwargs['cloud_id'] or kibana_kwargs['kibana_url']:
            client_error("Missing required --cloud-id or --kibana-url")

        # don't prompt for these until there's a cloud id or Kibana URL
        kibana_user = kibana_kwargs.pop('kibana_user', None) or click.prompt("kibana_user")
        kibana_password = kibana_kwargs.pop('kibana_password', None) or click.prompt("kibana_password", hide_input=True)

        with Kibana(**kibana_kwargs) as kibana:
            kibana.login(kibana_user, kibana_password)
            ctx.obj['kibana'] = kibana


@kibana_group.command("upload-rule")
@click.argument("toml-files", nargs=-1, required=True)
@click.pass_context
def upload_rule(ctx, toml_files):
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
        payload["rule_id"] = str(uuid4())
        payload = downgrade(payload, kibana.version)
        rule = RuleResource(payload)
        api_payloads.append(rule)

    rules = RuleResource.bulk_create(api_payloads)
    click.echo(f"Successfully uploaded {len(rules)} rules")
