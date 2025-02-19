# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Elasticsearch cli commands."""
import json
import sys
from collections import defaultdict
from typing import List, Union

import click
import elasticsearch
from elasticsearch import Elasticsearch
from elasticsearch.client import AsyncSearchClient

import kql
from .config import parse_rules_config
from .main import root
from .misc import add_params, client_error, elasticsearch_options, get_elasticsearch_client, nested_get
from .rule import TOMLRule
from .rule_loader import RuleCollection
from .utils import format_command_options, unix_time_to_formatted, get_path


COLLECTION_DIR = get_path('collections')
MATCH_ALL = {'bool': {'filter': [{'match_all': {}}]}}
RULES_CONFIG = parse_rules_config()


def add_range_to_dsl(dsl_filter, start_time, end_time='now'):
    dsl_filter.append(
        {"range": {"@timestamp": {"gt": start_time, "lte": end_time, "format": "strict_date_optional_time"}}}
    )


def parse_unique_field_results(rule_type: str, unique_fields: List[str], search_results: dict):
    parsed_results = defaultdict(lambda: defaultdict(int))
    hits = search_results['hits']
    hits = hits['hits'] if rule_type != 'eql' else hits.get('events') or hits.get('sequences', [])
    for hit in hits:
        for field in unique_fields:
            if 'events' in hit:
                match = []
                for event in hit['events']:
                    matched = nested_get(event['_source'], field)
                    match.extend([matched] if not isinstance(matched, list) else matched)
                    if not match:
                        continue
            else:
                match = nested_get(hit['_source'], field)
                if not match:
                    continue

            match = ','.join(sorted(match)) if isinstance(match, list) else match
            parsed_results[field][match] += 1
    # if rule.type == eql, structure is different
    return {'results': parsed_results} if parsed_results else {}


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
        last_event = self.client.search(query=dsl, index=index_str, size=1, sort='@timestamp:desc')['hits']['hits']
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
            raise ValueError(f'Unknown search language: {language}')

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

    def search_from_rule(self, rules: RuleCollection, start_time=None, end_time='now', size=None):
        """Search an elasticsearch instance using a rule."""
        async_client = AsyncSearchClient(self.client)
        survey_results = {}
        multi_search = []
        multi_search_rules = []
        async_searches = []
        eql_searches = []

        for rule in rules:
            if not rule.contents.data.get('query'):
                continue

            language = rule.contents.data.get('language')
            query = rule.contents.data.query
            rule_type = rule.contents.data.type
            index_str, formatted_dsl, lucene_query = self._prep_query(query=query,
                                                                      language=language,
                                                                      index=rule.contents.data.get('index', '*'),
                                                                      start_time=start_time,
                                                                      end_time=end_time)
            formatted_dsl.update(size=size or self.max_events)

            # prep for searches: msearch for kql | async search for lucene | eql client search for eql
            if language == 'kuery':
                multi_search_rules.append(rule)
                multi_search.append({'index': index_str, 'allow_no_indices': 'true', 'ignore_unavailable': 'true'})
                multi_search.append(formatted_dsl)
            elif language == 'lucene':
                # wait for 0 to try and force async with no immediate results (not guaranteed)
                result = async_client.submit(body=formatted_dsl, q=query, index=index_str,
                                             allow_no_indices=True, ignore_unavailable=True,
                                             wait_for_completion_timeout=0)
                if result['is_running'] is True:
                    async_searches.append((rule, result['id']))
                else:
                    survey_results[rule.id] = parse_unique_field_results(rule_type, ['process.name'],
                                                                         result['response'])
            elif language == 'eql':
                eql_body = {
                    'index': index_str,
                    'params': {'ignore_unavailable': 'true', 'allow_no_indices': 'true'},
                    'body': {'query': query, 'filter': formatted_dsl['filter']}
                }
                eql_searches.append((rule, eql_body))

        # assemble search results
        multi_search_results = self.client.msearch(searches=multi_search)
        for index, result in enumerate(multi_search_results['responses']):
            try:
                rule = multi_search_rules[index]
                survey_results[rule.id] = parse_unique_field_results(rule.contents.data.type,
                                                                     rule.contents.data.unique_fields, result)
            except KeyError:
                survey_results[multi_search_rules[index].id] = {'error_retrieving_results': True}

        for entry in eql_searches:
            rule: TOMLRule
            search_args: dict
            rule, search_args = entry
            try:
                result = self.client.eql.search(**search_args)
                survey_results[rule.id] = parse_unique_field_results(rule.contents.data.type,
                                                                     rule.contents.data.unique_fields, result)
            except (elasticsearch.NotFoundError, elasticsearch.RequestError) as e:
                survey_results[rule.id] = {'error_retrieving_results': True, 'error': e.info['error']['reason']}

        for entry in async_searches:
            rule: TOMLRule
            rule, async_id = entry
            result = async_client.get(id=async_id)['response']
            survey_results[rule.id] = parse_unique_field_results(rule.contents.data.type, ['process.name'], result)

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

    def count_from_rule(self, rules: RuleCollection, start_time=None, end_time='now'):
        """Get a count of documents from elasticsearch using a rule."""
        survey_results = {}

        for rule in rules.rules:
            rule_results = {'rule_id': rule.id, 'name': rule.name}

            if not rule.contents.data.get('query'):
                continue

            try:
                rule_results['search_count'] = self.count(query=rule.contents.data.query,
                                                          language=rule.contents.data.language,
                                                          index=rule.contents.data.get('index', '*'),
                                                          start_time=start_time,
                                                          end_time=end_time)
            except (elasticsearch.NotFoundError, elasticsearch.RequestError):
                rule_results['search_count'] = -1

            survey_results[rule.id] = rule_results

        return survey_results


@root.group('es')
@add_params(*elasticsearch_options)
@click.pass_context
def es_group(ctx: click.Context, **kwargs):
    """Commands for integrating with Elasticsearch."""
    ctx.ensure_object(dict)

    # only initialize an es client if the subcommand is invoked without help (hacky)
    if sys.argv[-1] in ctx.help_option_names:
        click.echo('Elasticsearch client:')
        click.echo(format_command_options(ctx))

    else:
        ctx.obj['es'] = get_elasticsearch_client(ctx=ctx, **kwargs)


@es_group.command('index-rules')
@click.option('--query', '-q', help='Optional KQL query to limit to specific rules')
@click.option('--from-file', '-f', type=click.File('r'), help='Load a previously saved uploadable bulk file')
@click.option('--save_files', '-s', is_flag=True, help='Optionally save the bulk request to a file')
@click.pass_context
def index_repo(ctx: click.Context, query, from_file, save_files):
    """Index rules based on KQL search results to an elasticsearch instance."""
    from .main import generate_rules_index

    es_client: Elasticsearch = ctx.obj['es']

    if from_file:
        bulk_upload_docs = from_file.read()

        # light validation only
        try:
            index_body = [json.loads(line) for line in bulk_upload_docs.splitlines()]
            click.echo(f'{len([r for r in index_body if "rule" in r])} rules included')
        except json.JSONDecodeError:
            client_error(f'Improperly formatted bulk request file: {from_file.name}')
    else:
        bulk_upload_docs, importable_rules_docs = ctx.invoke(generate_rules_index, query=query, save_files=save_files)

    es_client.bulk(bulk_upload_docs)


@es_group.group('experimental')
def es_experimental():
    """[Experimental] helper commands for integrating with Elasticsearch."""
    click.secho('\n* experimental commands are use at your own risk and may change without warning *\n')
