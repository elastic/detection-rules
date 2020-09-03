# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Elasticsearch cli and tmp."""
import json
import os
import time

import click
from elasticsearch import AuthenticationException, Elasticsearch
from kibana import Kibana, RuleResource

from .main import root
from .misc import set_param_values
from .utils import normalize_timing_and_sort, unix_time_to_formatted, get_path
from .rule_loader import get_rule, rta_mappings, load_rule_files, load_rules

COLLECTION_DIR = get_path('collections')
ERRORS = {
    'NO_EVENTS': 1,
    'FAILED_ES_AUTH': 2
}


@root.group('es')
def es_group():
    """Helper commands for integrating with Elasticsearch."""


def get_es_client(user, password, elasticsearch_url=None, cloud_id=None, **kwargs):
    """Get an auth-validated elsticsearch client."""
    assert elasticsearch_url or cloud_id, \
        'You must specify a host or cloud_id to authenticate to an elasticsearch instance'

    hosts = [elasticsearch_url] if elasticsearch_url else elasticsearch_url

    client = Elasticsearch(hosts=hosts, cloud_id=cloud_id, http_auth=(user, password), **kwargs)
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


@es_group.command('collect-events')
@click.argument('agent-hostname')
@click.option('--elasticsearch-url', '-u', callback=set_param_values, expose_value=True)
@click.option('--cloud-id', callback=set_param_values, expose_value=True)
@click.option('--user', '-u', callback=set_param_values, expose_value=True, hide_input=False)
@click.option('--password', '-p', callback=set_param_values, expose_value=True, hide_input=True)
@click.option('--index', '-i', multiple=True, help='Index(es) to search against (default: all indexes)')
@click.option('--agent-type', '-a', help='Restrict results to a source type (agent.type) ex: auditbeat')
@click.option('--rta-name', '-r', help='Name of RTA in order to save events directly to unit tests data directory')
@click.option('--rule-id', help='Updates rule mapping in rule-mapping.yml file (requires --rta-name)')
@click.option('--view-events', is_flag=True, help='Print events after saving')
def collect_events(agent_hostname, elasticsearch_url, cloud_id, user, password, index, agent_type, rta_name, rule_id,
                   view_events):
    """Collect events from Elasticsearch."""
    match = {'agent.type': agent_type} if agent_type else {}

    try:
        client = get_es_client(elasticsearch_url=elasticsearch_url, use_ssl=True, cloud_id=cloud_id, user=user,
                               password=password)
    except AuthenticationException:
        click.secho('Failed authentication for {}'.format(elasticsearch_url or cloud_id), fg='red', err=True)
        return ERRORS['FAILED_ES_AUTH']

    try:
        collector = CollectEvents(client)
        events = collector.run(agent_hostname, index, **match)
        events.save(rta_name)
    except AssertionError:
        click.secho('No events collected! Verify events are streaming and that the agent-hostname is correct',
                    err=True, fg='red')
        return ERRORS['NO_EVENTS']

    if rta_name and rule_id:
        events.evaluate_against_rule_and_update_mapping(rule_id, rta_name)

    if view_events and events.events:
        events.echo_events(pager=True)

    return events


@es_group.command('normalize-data')
@click.argument('events-file', type=click.File('r'))
def normalize_file(events_file):
    """Normalize Elasticsearch data timestamps and sort."""
    file_name = os.path.splitext(os.path.basename(events_file.name))[0]
    events = Events('_', {file_name: [json.loads(e) for e in events_file.readlines()]})
    events.save(dump_dir=os.path.dirname(events_file.name))


@root.command("kibana-upload")
@click.argument("toml-files", nargs=-1, required=True)
@click.option('--kibana-url', '-u', callback=set_param_values, expose_value=True)
@click.option('--cloud-id', callback=set_param_values, expose_value=True)
@click.option('--user', '-u', callback=set_param_values, expose_value=True, hide_input=False)
@click.option('--password', '-p', callback=set_param_values, expose_value=True, hide_input=True)
@click.option('--space', callback=set_param_values, expose_value=True, hide_input=False)
def kibana_upload(toml_files, kibana_url, cloud_id, user, password, space):
    """Upload a list of rule .toml files to Kibana."""
    from uuid import uuid4
    from .packaging import manage_versions
    from .schemas import downgrade

    # Update kibana url if a space is defined
    if space:
        print("Kibana url would be: {}/s/{}".format(kibana_url, space))

    with Kibana(cloud_id=cloud_id, url=kibana_url) as kibana:
        kibana.login(user, password)

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
