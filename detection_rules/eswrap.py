# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Elasticsearch cli commands."""
import json
import os
import time
from contextlib import contextmanager
from pathlib import Path

import click
import elasticsearch
from elasticsearch import AuthenticationException, Elasticsearch
from elasticsearch.client import IngestClient, MlClient

from .main import root
from .misc import client_error, getdefault
from .utils import format_command_options, normalize_timing_and_sort, unix_time_to_formatted, get_path
from .rule_loader import get_rule, rta_mappings

COLLECTION_DIR = get_path('collections')


def get_es_client(es_user, es_password, elasticsearch_url=None, cloud_id=None, **kwargs):
    """Get an auth-validated elasticsearch client."""
    assert elasticsearch_url or cloud_id, \
        'You must specify a host or cloud_id to authenticate to an elasticsearch instance'

    hosts = [elasticsearch_url] if elasticsearch_url else elasticsearch_url

    timeout = kwargs.pop('timeout', 60)
    client = Elasticsearch(hosts=hosts, cloud_id=cloud_id, http_auth=(es_user, es_password), timeout=timeout, **kwargs)
    # force login to test auth
    client.info()
    return client


class Events(object):
    """Events collected from Elasticsearch."""

    def __init__(self, agent_hostname, events):
        self.agent_hostname = agent_hostname
        self.events = self._normalize_event_timing(events)

    @staticmethod
    def _normalize_event_timing(events):
        """Normalize event timestamps and sort."""
        for agent_type, _events in events.items():
            events[agent_type] = normalize_timing_and_sort(_events)

        return events

    def _get_dump_dir(self, rta_name=None):
        """Prepare and get the dump path."""
        if rta_name:
            dump_dir = get_path('unit_tests', 'data', 'true_positives', rta_name)
            os.makedirs(dump_dir, exist_ok=True)
            return dump_dir
        else:
            time_str = time.strftime('%Y%m%dT%H%M%SL')
            dump_dir = os.path.join(COLLECTION_DIR, self.agent_hostname, time_str)
            os.makedirs(dump_dir, exist_ok=True)
            return dump_dir

    def evaluate_against_rule_and_update_mapping(self, rule_id, rta_name, verbose=True):
        """Evaluate a rule against collected events and update mapping."""
        from .utils import combine_sources, evaluate

        rule = get_rule(rule_id, verbose=False)
        merged_events = combine_sources(*self.events.values())
        filtered = evaluate(rule, merged_events)

        if filtered:
            sources = [e['agent']['type'] for e in filtered]
            mapping_update = rta_mappings.add_rule_to_mapping_file(rule, len(filtered), rta_name, *sources)

            if verbose:
                click.echo('Updated rule-mapping file with: \n{}'.format(json.dumps(mapping_update, indent=2)))
        else:
            if verbose:
                click.echo('No updates to rule-mapping file; No matching results')

    def echo_events(self, pager=False, pretty=True):
        """Print events to stdout."""
        echo_fn = click.echo_via_pager if pager else click.echo
        echo_fn(json.dumps(self.events, indent=2 if pretty else None, sort_keys=True))

    def save(self, rta_name=None, dump_dir=None):
        """Save collected events."""
        assert self.events, 'Nothing to save. Run Collector.run() method first'

        dump_dir = dump_dir or self._get_dump_dir(rta_name)

        for source, events in self.events.items():
            path = os.path.join(dump_dir, source + '.jsonl')
            with open(path, 'w') as f:
                f.writelines([json.dumps(e, sort_keys=True) + '\n' for e in events])
                click.echo('{} events saved to: {}'.format(len(events), path))


class CollectEvents(object):
    """Event collector for elastic stack."""

    def __init__(self, client, max_events=3000):
        self.client = client
        self.MAX_EVENTS = max_events

    def _build_timestamp_map(self, index_str):
        """Build a mapping of indexes to timestamp data formats."""
        mappings = self.client.indices.get_mapping(index=index_str)
        timestamp_map = {n: m['mappings'].get('properties', {}).get('@timestamp', {}) for n, m in mappings.items()}
        return timestamp_map

    def _get_current_time(self, agent_hostname, index_str):
        """Get timestamp of most recent event."""
        # https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-date-format.html
        timestamp_map = self._build_timestamp_map(index_str)

        last_event = self._search_window(agent_hostname, index_str, start_time='now-1m', size=1, sort='@timestamp:desc')
        last_event = last_event['hits']['hits'][0]

        index = last_event['_index']
        timestamp = last_event['_source']['@timestamp']
        event_date_format = timestamp_map[index].get('format', '').split('||')

        # there are many native supported date formats and even custom data formats, but most, including beats use the
        # default `strict_date_optional_time`. It would be difficult to try to account for all possible formats, so this
        # will work on the default and unix time.
        if set(event_date_format) & {'epoch_millis', 'epoch_second'}:
            timestamp = unix_time_to_formatted(timestamp)

        return timestamp

    def _search_window(self, agent_hostname, index_str, start_time, end_time='now', size=None, sort='@timestamp:asc',
                       **match):
        """Collect all events within a time window and parse by source."""
        match = match.copy()
        match.update({"agent.hostname": agent_hostname})
        body = {"query": {"bool": {"filter": [
            {"match": {"agent.hostname": agent_hostname}},
            {"range": {"@timestamp": {"gt": start_time, "lte": end_time, "format": "strict_date_optional_time"}}}]
        }}}

        if match:
            body['query']['bool']['filter'].extend([{'match': {k: v}} for k, v in match.items()])

        return self.client.search(index=index_str, body=body, size=size or self.MAX_EVENTS, sort=sort)

    @staticmethod
    def _group_events_by_type(events):
        """Group events by agent.type."""
        event_by_type = {}

        for event in events['hits']['hits']:
            event_by_type.setdefault(event['_source']['agent']['type'], []).append(event['_source'])

        return event_by_type

    def run(self, agent_hostname, indexes, verbose=True, **match):
        """Collect the events."""
        index_str = ','.join(indexes)
        start_time = self._get_current_time(agent_hostname, index_str)

        if verbose:
            click.echo('Setting start of event capture to: {}'.format(click.style(start_time, fg='yellow')))

        click.pause('Press any key once detonation is complete ...')
        time.sleep(5)
        events = self._group_events_by_type(self._search_window(agent_hostname, index_str, start_time, **match))

        return Events(agent_hostname, events)


@root.command('normalize-data')
@click.argument('events-file', type=click.File('r'))
def normalize_data(events_file):
    """Normalize Elasticsearch data timestamps and sort."""
    file_name = os.path.splitext(os.path.basename(events_file.name))[0]
    events = Events('_', {file_name: [json.loads(e) for e in events_file.readlines()]})
    events.save(dump_dir=os.path.dirname(events_file.name))


@root.group('es')
@click.option('--elasticsearch-url', '-e', default=getdefault("elasticsearch_url"))
@click.option('--cloud-id', default=getdefault("cloud_id"))
@click.option('--es-user', '-u', default=getdefault("es_user"))
@click.option('--es-password', '-p', default=getdefault("es_password"))
@click.option('--timeout', '-t', default=60, help='Timeout for elasticsearch client')
@click.pass_context
def es_group(ctx: click.Context, **es_kwargs):
    """Commands for integrating with Elasticsearch."""
    ctx.ensure_object(dict)

    # only initialize an es client if the subcommand is invoked without help (hacky)
    if click.get_os_args()[-1] in ctx.help_option_names:
        click.echo('Elasticsearch client:')
        click.echo(format_command_options(ctx))

    else:
        if not es_kwargs['cloud_id'] or es_kwargs['elasticsearch_url']:
            client_error("Missing required --cloud-id or --elasticsearch-url")

        # don't prompt for these until there's a cloud id or elasticsearch URL
        es_kwargs['es_user'] = es_kwargs['es_user'] or click.prompt("es_user")
        es_kwargs['es_password'] = es_kwargs['es_password'] or click.prompt("es_password", hide_input=True)

        try:
            client = get_es_client(use_ssl=True, **es_kwargs)
            ctx.obj['es'] = client
        except AuthenticationException as e:
            error_msg = f'Failed authentication for {es_kwargs.get("elasticsearch_url") or es_kwargs.get("cloud_id")}'
            client_error(error_msg, e, ctx=ctx, err=True)


@es_group.command('collect-events')
@click.argument('agent-hostname')
@click.option('--index', '-i', multiple=True, help='Index(es) to search against (default: all indexes)')
@click.option('--agent-type', '-a', help='Restrict results to a source type (agent.type) ex: auditbeat')
@click.option('--rta-name', '-r', help='Name of RTA in order to save events directly to unit tests data directory')
@click.option('--rule-id', help='Updates rule mapping in rule-mapping.yml file (requires --rta-name)')
@click.option('--view-events', is_flag=True, help='Print events after saving')
@click.pass_context
def collect_events(ctx, agent_hostname, index, agent_type, rta_name, rule_id, view_events):
    """Collect events from Elasticsearch."""
    match = {'agent.type': agent_type} if agent_type else {}
    client = ctx.obj['es']

    try:
        collector = CollectEvents(client)
        events = collector.run(agent_hostname, index, **match)
        events.save(rta_name)

        if rta_name and rule_id:
            events.evaluate_against_rule_and_update_mapping(rule_id, rta_name)

        if view_events and events.events:
            events.echo_events(pager=True)

        return events
    except AssertionError as e:
        error_msg = 'No events collected! Verify events are streaming and that the agent-hostname is correct'
        client_error(error_msg, e, ctx=ctx)


@es_group.group('beta')
def es_beta():
    """BETA helper commands for integrating with Elasticsearch."""


@es_beta.command('remove-ml-dga')
@click.argument('model-id')
@click.option('--force', '-f', is_flag=True, help='Force the attempted delete without checking if model exists')
@click.pass_context
def remove_ml_dga(ctx, model_id, force, es_client: Elasticsearch = None, ml_client: MlClient = None,
                  ingest_client: IngestClient = None):
    """Remove ML DGA files."""
    from elasticsearch.client import IngestClient, MlClient

    es_client = es_client or ctx.obj['es']
    ml_client = ml_client or MlClient(es_client)
    ingest_client = ingest_client or IngestClient(es_client)

    def safe_delete(func, fid, verbose=True):
        try:
            func(fid)
        except elasticsearch.NotFoundError:
            return False
        if verbose:
            click.echo(f' - {fid} deleted')
        return True

    model_exists = False
    if not force:
        existing_models = ml_client.get_trained_models()
        model_exists = model_id in [m['model_id'] for m in existing_models.get('trained_model_configs', [])]

    if model_exists or force:
        if model_exists:
            click.secho('[-] Existing model detected - deleting files', fg='yellow')

        deleted = [
            safe_delete(ingest_client.delete_pipeline, 'dga_ngram_expansion_inference'),
            safe_delete(ingest_client.delete_pipeline, 'dns_classification_pipeline'),
            safe_delete(es_client.delete_script, 'ngram-extractor-packetbeat'),
            safe_delete(es_client.delete_script, 'ngram-remover-packetbeat'),
            safe_delete(ml_client.delete_trained_model, model_id)
        ]

        if not any(deleted):
            click.echo('No files deleted')
    else:
        click.echo(f'Model: {model_id} not found')


@es_beta.command('setup-ml-dga')
@click.option('--model-tag', '-t',
              help='Release tag for model files staged in detection-rules (required to download files)')
@click.option('--repo', '-r', default='elastic/detection-rules',
              help='Repo hosting the model file releases (owner/repo)')
@click.option('--model-dir', '-d', type=click.Path(exists=True, file_okay=False),
              help='Directory containing local model files')
@click.option('--overwrite', is_flag=True, help='Overwrite all files if already in the stack')
@click.pass_context
def setup_ml_dga(ctx, model_tag, repo, model_dir, overwrite):
    """Upload ML DGA model and dependencies and enrich DNS data."""
    import io
    import requests
    import shutil
    import zipfile

    es_client: Elasticsearch = ctx.obj['es']
    client_info = es_client.info()

    # download files if necessary
    if not model_dir:
        if not model_tag:
            client_error('model-tag or model-dir required to download model files')

        click.echo(f'Downloading artifact: {model_tag}')

        release_url = f'https://api.github.com/repos/{repo}/releases/tags/{model_tag}'
        release = requests.get(release_url)
        release.raise_for_status()

        zipped_url = release.json()['assets'][0]['browser_download_url']
        zipped = requests.get(zipped_url)
        z = zipfile.ZipFile(io.BytesIO(zipped.content))

        dga_dir = get_path('ML-models', 'DGA')
        model_dir = os.path.join(dga_dir, model_tag)
        os.makedirs(dga_dir, exist_ok=True)
        shutil.rmtree(model_dir, ignore_errors=True)
        z.extractall(dga_dir)
        click.echo(f'files saved to {model_dir}')

        # read files as needed
        z.close()

    @contextmanager
    def open_model_file(pattern, name_only=False):
        paths = list(Path(model_dir).glob(pattern))
        if not paths:
            client_error(f'{model_dir} missing files matching the pattern: {pattern}')
        if len(paths) > 1:
            client_error(f'{model_dir} contains multiple files matching the pattern: {pattern}')

        if name_only:
            yield paths[0]
        else:
            with open(paths[0], 'r') as f:
                yield json.load(f)

    with open_model_file('dga_*_model.json', name_only=True) as model_file:
        model_id, _ = os.path.basename(model_file).rsplit('_', maxsplit=1)

    click.echo(f'Setting up DGA model: "{model_id}" on {client_info["name"]} ({client_info["version"]["number"]})')

    # upload model
    ml_client = MlClient(es_client)
    ingest_client = IngestClient(es_client)

    existing_models = ml_client.get_trained_models()
    if model_id in [m['model_id'] for m in existing_models.get('trained_model_configs', [])]:
        if overwrite:
            ctx.invoke(remove_ml_dga, model_id=model_id, es_client=es_client, ml_client=ml_client,
                       ingest_client=ingest_client, force=True)
        else:
            client_error(f'Model: {model_id} already exists on stack! Try --overwrite to force the upload')

    click.secho('[+] Uploading model (may take a while)')

    with open_model_file('dga_*_model.json') as model_file:
        try:
            ml_client.put_trained_model(model_id=model_id, body=model_file)
        except elasticsearch.ConnectionTimeout:
            client_error('Connection timeout, try increasing timeout using `es --timeout <secs> beta setup-ml-dga`.')

    # install scripts
    click.secho('[+] Uploading painless scripts')

    with open_model_file('dga_*_ngrams_create.json') as painless_install:
        es_client.put_script(id='ngram-extractor-packetbeat', body=painless_install)

    with open_model_file('dga_*_ngrams_delete.json') as painless_delete:
        es_client.put_script(id='ngram-remover-packetbeat', body=painless_delete)

    # Install ingest pipelines
    click.secho('[+] Uploading pipelines')

    def _build_es_script_error(err, pipeline_file):
        error = err.info['error']
        cause = error['caused_by']

        error_msg = [
            f'Script error while uploading {pipeline_file}: {cause["type"]} - {cause["reason"]}',
            ' '.join(f'{k}: {v}' for k, v in error['position'].items()),
            '\n'.join(error['script_stack'])
        ]

        return click.style('\n'.join(error_msg), fg='red')

    with open_model_file('dga_*_ingest_pipeline1.json') as ingest_pipeline1:
        processors = ingest_pipeline1['processors']
        inference_processor = next(p for p in processors if 'inference' in p)
        inference_processor['inference']['model_id'] = model_id
        try:
            ingest_client.put_pipeline(id='dga_ngram_expansion_inference', body=ingest_pipeline1)
        except elasticsearch.RequestError as e:
            if e.error == 'script_exception':
                client_error(_build_es_script_error(e, 'ingest_pipeline1'), e, ctx=ctx)
            else:
                raise

    with open_model_file('dga_*_ingest_pipeline2.json') as ingest_pipeline2:
        try:
            ingest_client.put_pipeline(id='dns_classification_pipeline', body=ingest_pipeline2)
        except elasticsearch.RequestError as e:
            if e.error == 'script_exception':
                client_error(_build_es_script_error(e, 'ingest_pipeline2'), e, ctx=ctx)
            else:
                raise
