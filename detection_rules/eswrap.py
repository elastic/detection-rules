# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Elasticsearch cli commands."""
import json
import os
import time
from collections import defaultdict
from typing import Union

import click
import elasticsearch
from elasticsearch import Elasticsearch
from elasticsearch.client import AsyncSearchClient

import kql
from .main import root
from .misc import add_params, client_error, elasticsearch_options
from .utils import format_command_options, normalize_timing_and_sort, unix_time_to_formatted, get_path
from .rule import Rule
from .rule_loader import get_rule, rta_mappings

COLLECTION_DIR = get_path('collections')
MATCH_ALL = {'bool': {'filter': [{'match_all': {}}]}}


def get_authed_es_client(cloud_id=None, elasticsearch_url=None, es_user=None, es_password=None, ctx=None, **kwargs):
    """Get an authenticated elasticsearch client."""
    if not (cloud_id or elasticsearch_url):
        client_error("Missing required --cloud-id or --elasticsearch-url")

    # don't prompt for these until there's a cloud id or elasticsearch URL
    es_user = es_user or click.prompt("es_user")
    es_password = es_password or click.prompt("es_password", hide_input=True)
    hosts = [elasticsearch_url] if elasticsearch_url else None

    try:
        client = Elasticsearch(hosts=hosts, cloud_id=cloud_id, http_auth=(es_user, es_password), **kwargs)
        # force login to test auth
        client.info()
        return client
    except elasticsearch.AuthenticationException as e:
        error_msg = f'Failed authentication for {elasticsearch_url or cloud_id}'
        client_error(error_msg, e, ctx=ctx, err=True)


def add_range_to_dsl(dsl_filter, start_time, end_time='now'):
    dsl_filter.append(
        {"range": {"@timestamp": {"gt": start_time, "lte": end_time, "format": "strict_date_optional_time"}}}
    )


class RtaEvents(object):
    """Events collected from Elasticsearch."""

    def __init__(self, events):
        self.events: dict = self._normalize_event_timing(events)

    @staticmethod
    def _normalize_event_timing(events):
        """Normalize event timestamps and sort."""
        for agent_type, _events in events.items():
            events[agent_type] = normalize_timing_and_sort(_events)

        return events

    @staticmethod
    def _get_dump_dir(rta_name=None, host_id=None):
        """Prepare and get the dump path."""
        if rta_name:
            dump_dir = get_path('unit_tests', 'data', 'true_positives', rta_name)
            os.makedirs(dump_dir, exist_ok=True)
            return dump_dir
        else:
            time_str = time.strftime('%Y%m%dT%H%M%SL')
            dump_dir = os.path.join(COLLECTION_DIR, host_id or 'unknown_host', time_str)
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

    def save(self, rta_name=None, dump_dir=None, host_id=None):
        """Save collected events."""
        assert self.events, 'Nothing to save. Run Collector.run() method first or verify logging'

        dump_dir = dump_dir or self._get_dump_dir(rta_name=rta_name, host_id=host_id)

        for source, events in self.events.items():
            path = os.path.join(dump_dir, source + '.jsonl')
            with open(path, 'w') as f:
                f.writelines([json.dumps(e, sort_keys=True) + '\n' for e in events])
                click.echo('{} events saved to: {}'.format(len(events), path))


class CollectEvents(object):
    """Event collector for elastic stack."""

    def __init__(self, client, max_events=3000):
        self.client: Elasticsearch = client
        self.max_events = max_events

    def _build_timestamp_map(self, index_str):
        """Build a mapping of indexes to timestamp data formats."""
        mappings = self.client.indices.get_mapping(index=index_str)
        timestamp_map = {n: m['mappings'].get('properties', {}).get('@timestamp', {}) for n, m in mappings.items()}
        return timestamp_map

    def _get_last_event_time(self, index_str, dsl=None):
        """Get timestamp of most recent event."""
        last_event = self.client.search(dsl, index_str, size=1, sort='@timestamp:desc')['hits']['hits']
        if not last_event:
            return

        last_event = last_event[0]
        index = last_event['_index']
        timestamp = last_event['_source']['@timestamp']

        timestamp_map = self._build_timestamp_map(index_str)
        event_date_format = timestamp_map[index].get('format', '').split('||')

        # there are many native supported date formats and even custom data formats, but most, including beats use the
        # default `strict_date_optional_time`. It would be difficult to try to account for all possible formats, so this
        # will work on the default and unix time.
        if set(event_date_format) & {'epoch_millis', 'epoch_second'}:
            timestamp = unix_time_to_formatted(timestamp)

        return timestamp

    @staticmethod
    def _prep_query(query, language, index, start_time=None, end_time=None):
        """Prep a query for search."""
        index_str = ','.join(index if isinstance(index, (list, tuple)) else index.split(','))
        lucene_query = query if language == 'lucene' else None

        if language in ('kql', 'kuery'):
            formatted_dsl = {'query': kql.to_dsl(query)}
        elif language == 'eql':
            formatted_dsl = {'query': query, 'filter': MATCH_ALL}
        elif language == 'lucene':
            formatted_dsl = {'query': {'bool': {'filter': []}}}
        elif language == 'dsl':
            formatted_dsl = {'query': query}
        else:
            raise ValueError('Unknown search language')

        if start_time or end_time:
            end_time = end_time or 'now'
            dsl = formatted_dsl['filter']['bool']['filter'] if language == 'eql' else \
                formatted_dsl['query']['bool'].setdefault('filter', [])
            add_range_to_dsl(dsl, start_time, end_time)

        return index_str, formatted_dsl, lucene_query

    def search(self, query, language, index: Union[str, list] = '*', start_time=None, end_time=None, size=None,
               **kwargs):
        """Search an elasticsearch instance."""
        index_str, formatted_dsl, lucene_query = self._prep_query(query=query, language=language, index=index,
                                                                  start_time=start_time, end_time=end_time)
        formatted_dsl.update(size=size or self.max_events)

        if language == 'eql':
            results = self.client.eql.search(body=formatted_dsl, index=index_str, **kwargs)['hits']
            results = results.get('events') or results.get('sequences', [])
        else:
            results = self.client.search(body=formatted_dsl, q=lucene_query, index=index_str,
                                         allow_no_indices=True, ignore_unavailable=True, **kwargs)['hits']['hits']

        return results

    def search_from_rule(self, *rules: Rule, start_time=None, end_time='now', size=None):
        """Search an elasticsearch instance using a rule."""
        from .misc import nested_get

        async_client = AsyncSearchClient(self.client)
        survey_results = {}

        def parse_unique_field_results(rule_type, unique_fields, search_results):
            parsed_results = defaultdict(lambda: defaultdict(int))
            hits = search_results['hits']['hits'] if rule_type != 'eql' else search_results.events
            for hit in hits:
                for field in unique_fields:
                    match = nested_get(hit['_source'], field)
                    match = ','.join(sorted(match)) if isinstance(match, list) else match
                    parsed_results[field][match] += 1
            # if rule.type == eql, structure is different
            return {'results': parsed_results} if parsed_results else {}

        multi_search = []
        multi_search_rules = []
        async_searches = {}
        eql_searches = {}

        for rule in rules:
            if not rule.query:
                continue

            index_str, formatted_dsl, lucene_query = self._prep_query(query=rule.query,
                                                                      language=rule.contents.get('language'),
                                                                      index=rule.contents.get('index', '*'),
                                                                      start_time=start_time,
                                                                      end_time=end_time)
            formatted_dsl.update(size=size or self.max_events)

            # prep for searches: msearch for kql | async search for lucene | eql client search for eql
            if rule.contents['language'] == 'kuery':
                multi_search_rules.append(rule)
                multi_search.append(json.dumps(
                    {'index': index_str, 'allow_no_indices': 'true', 'ignore_unavailable': 'true'}))
                multi_search.append(json.dumps(formatted_dsl))
            elif rule.contents['language'] == 'lucene':
                # wait for 0 to try and force async with no immediate results (not guaranteed)
                result = async_client.submit(body=formatted_dsl, q=rule.query, index=index_str,
                                             allow_no_indices=True, ignore_unavailable=True,
                                             wait_for_completion_timeout=0)
                if result['is_running'] is True:
                    async_searches[rule] = result['id']
                else:
                    survey_results[rule.id] = parse_unique_field_results(rule.type, rule.unique_fields,
                                                                         result['response'])
            elif rule.contents['language'] == 'eql':
                eql_body = {
                    'index': index_str,
                    'params': {'ignore_unavailable': 'true', 'allow_no_indices': 'true'},
                    'body': {'query': rule.query, 'filter': formatted_dsl['filter']}
                }
                eql_searches[rule] = eql_body

        # assemble search results
        multi_search_results = self.client.msearch('\n'.join(multi_search) + '\n')
        for index, result in enumerate(multi_search_results['responses']):
            try:
                rule = multi_search_rules[index]
                survey_results[rule.id] = parse_unique_field_results(rule.type, rule.unique_fields, result)
            except KeyError:
                survey_results[multi_search_rules[index].id] = {'error_retrieving_results': True}

        for rule, search_args in eql_searches.items():
            try:
                result = self.client.eql.search(**search_args)
                survey_results[rule.id] = parse_unique_field_results(rule.type, rule.unique_fields, result)
            except (elasticsearch.NotFoundError, elasticsearch.RequestError) as e:
                survey_results[rule.id] = {'error_retrieving_results': True, 'error': e.info['error']['reason']}

        for rule, async_id in async_searches.items():
            result = async_client.get(async_id)['response']
            survey_results[rule.id] = parse_unique_field_results(rule.type, rule.unique_fields, result)

        return survey_results

    def count(self, query, language, index: Union[str, list], start_time=None, end_time='now'):
        """Get a count of documents from elasticsearch."""
        index_str, formatted_dsl, lucene_query = self._prep_query(query=query, language=language, index=index,
                                                                  start_time=start_time, end_time=end_time)

        # EQL API has no count endpoint
        if language == 'eql':
            results = self.search(query=query, language=language, index=index, start_time=start_time, end_time=end_time,
                                  size=1000)
            return len(results)
        else:
            return self.client.count(body=formatted_dsl, index=index_str, q=lucene_query, allow_no_indices=True,
                                     ignore_unavailable=True)['count']

    def count_from_rule(self, *rules, start_time=None, end_time='now'):
        """Get a count of documents from elasticsearch using a rule."""
        survey_results = {}

        for rule in rules:
            rule_results = {'rule_id': rule.id, 'name': rule.name}

            if not rule.query:
                continue

            try:
                rule_results['search_count'] = self.count(query=rule.query, language=rule.contents.get('language'),
                                                          index=rule.contents.get('index', '*'), start_time=start_time,
                                                          end_time=end_time)
            except (elasticsearch.NotFoundError, elasticsearch.RequestError):
                rule_results['search_count'] = -1

            survey_results[rule.id] = rule_results

        return survey_results


class CollectRtaEvents(CollectEvents):
    """Collect RTA events from elasticsearch."""

    @staticmethod
    def _group_events_by_type(events):
        """Group events by agent.type."""
        event_by_type = {}

        for event in events:
            event_by_type.setdefault(event['_source']['agent']['type'], []).append(event['_source'])

        return event_by_type

    def run(self, dsl, indexes, start_time):
        """Collect the events."""
        results = self.search(dsl, language='dsl', index=indexes, start_time=start_time, end_time='now', size=5000,
                              sort='@timestamp:asc')
        events = self._group_events_by_type(results)
        return RtaEvents(events)


@root.command('normalize-data')
@click.argument('events-file', type=click.File('r'))
def normalize_data(events_file):
    """Normalize Elasticsearch data timestamps and sort."""
    file_name = os.path.splitext(os.path.basename(events_file.name))[0]
    events = RtaEvents({file_name: [json.loads(e) for e in events_file.readlines()]})
    events.save(dump_dir=os.path.dirname(events_file.name))


@root.group('es')
@add_params(*elasticsearch_options)
@click.pass_context
def es_group(ctx: click.Context, **kwargs):
    """Commands for integrating with Elasticsearch."""
    ctx.ensure_object(dict)

    # only initialize an es client if the subcommand is invoked without help (hacky)
    if click.get_os_args()[-1] in ctx.help_option_names:
        click.echo('Elasticsearch client:')
        click.echo(format_command_options(ctx))

    else:
        ctx.obj['es'] = get_authed_es_client(ctx=ctx, **kwargs)


@es_group.command('collect-events')
@click.argument('host-id')
@click.option('--query', '-q', help='KQL query to scope search')
@click.option('--index', '-i', multiple=True, help='Index(es) to search against (default: all indexes)')
@click.option('--rta-name', '-r', help='Name of RTA in order to save events directly to unit tests data directory')
@click.option('--rule-id', help='Updates rule mapping in rule-mapping.yml file (requires --rta-name)')
@click.option('--view-events', is_flag=True, help='Print events after saving')
@click.pass_context
def collect_events(ctx, host_id, query, index, rta_name, rule_id, view_events):
    """Collect events from Elasticsearch."""
    client = ctx.obj['es']
    dsl = kql.to_dsl(query) if query else MATCH_ALL
    dsl['bool'].setdefault('filter', []).append({'bool': {'should': [{'match_phrase': {'host.id': host_id}}]}})

    try:
        collector = CollectRtaEvents(client)
        start = time.time()
        click.pause('Press any key once detonation is complete ...')
        start_time = f'now-{round(time.time() - start) + 5}s'
        events = collector.run(dsl, index or '*', start_time)
        events.save(rta_name=rta_name, host_id=host_id)

        if rta_name and rule_id:
            events.evaluate_against_rule_and_update_mapping(rule_id, rta_name)

        if view_events and events.events:
            events.echo_events(pager=True)

        return events
    except AssertionError as e:
        error_msg = 'No events collected! Verify events are streaming and that the agent-hostname is correct'
        client_error(error_msg, e, ctx=ctx)
