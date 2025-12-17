# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Elasticsearch cli commands."""

import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import IO, Any

import click
import elasticsearch
import kql  # type: ignore[reportMissingTypeStubs]
from elasticsearch import Elasticsearch
from elasticsearch.client import AsyncSearchClient

from .config import parse_rules_config
from .main import root
from .misc import add_params, elasticsearch_options, get_elasticsearch_client, nested_get, raise_client_error
from .rule import TOMLRule
from .rule_loader import RuleCollection
from .utils import event_sort, format_command_options, get_path, normalize_timing_and_sort, unix_time_to_formatted

COLLECTION_DIR = get_path(["collections"])
MATCH_ALL: dict[str, dict[str, Any]] = {"bool": {"filter": [{"match_all": {}}]}}
RULES_CONFIG = parse_rules_config()


def add_range_to_dsl(dsl_filter: list[dict[str, Any]], start_time: str, end_time: str = "now") -> None:
    dsl_filter.append(
        {
            "range": {
                "@timestamp": {
                    "gt": start_time,
                    "lte": end_time,
                    "format": "strict_date_optional_time",
                },
            },
        }
    )


def parse_unique_field_results(
    rule_type: str,
    unique_fields: list[str],
    search_results: dict[str, Any],
) -> dict[str, Any]:
    parsed_results: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    hits = search_results["hits"]
    hits = hits["hits"] if rule_type != "eql" else hits.get("events") or hits.get("sequences", [])
    for hit in hits:
        for field in unique_fields:
            if "events" in hit:
                match: list[Any] = []
                for event in hit["events"]:
                    matched = nested_get(event["_source"], field)
                    match.extend([matched] if not isinstance(matched, list) else matched)  # type: ignore[reportUnknownArgumentType]
                    if not match:
                        continue
            else:
                match = nested_get(hit["_source"], field)
                if not match:
                    continue

            match = ",".join(sorted(match)) if isinstance(match, list) else match  # type: ignore[reportUnknownArgumentType]
            parsed_results[field][match] += 1  # type: ignore[reportUnknownArgumentType]
    # if rule.type == eql, structure is different
    return {"results": parsed_results} if parsed_results else {}


class Events:
    """Events collected from Elasticsearch."""

    def __init__(self, events: dict[str, Any]) -> None:
        self.events = self._normalize_event_timing(events)

    @staticmethod
    def _normalize_event_timing(events: dict[str, Any]) -> dict[str, Any]:
        """Normalize event timestamps and sort."""
        for agent_type, _events in events.items():
            events[agent_type] = normalize_timing_and_sort(_events)

        return events

    @staticmethod
    def _get_dump_dir(
        rta_name: str | None = None,
        host_id: str | None = None,
        host_os_family: str | None = None,
    ) -> Path:
        """Prepare and get the dump path."""
        if rta_name and host_os_family:
            dump_dir = get_path(["unit_tests", "data", "true_positives", rta_name, host_os_family])
            dump_dir.mkdir(parents=True, exist_ok=True)
            return dump_dir
        time_str = time.strftime("%Y%m%dT%H%M%SL")
        dump_dir = COLLECTION_DIR / (host_id or "unknown_host") / time_str
        dump_dir.mkdir(parents=True, exist_ok=True)
        return dump_dir

    def evaluate_against_rule(self, rule_id: str, verbose: bool = True) -> list[Any]:
        """Evaluate a rule against collected events and update mapping."""
        rule = RuleCollection.default().id_map.get(rule_id)
        if not rule:
            raise ValueError(f"Unable to find rule with ID {rule_id}")
        merged_events = combine_sources(*self.events.values())
        filtered = evaluate(rule, merged_events, normalize_kql_keywords=RULES_CONFIG.normalize_kql_keywords)

        if verbose:
            click.echo("Matching results found")

        return filtered

    def echo_events(self, pager: bool = False, pretty: bool = True) -> None:
        """Print events to stdout."""
        echo_fn = click.echo_via_pager if pager else click.echo
        echo_fn(json.dumps(self.events, indent=2 if pretty else None, sort_keys=True))

    def save(self, rta_name: str | None = None, dump_dir: Path | None = None, host_id: str | None = None) -> None:
        """Save collected events."""
        if not self.events:
            raise ValueError("Nothing to save. Run Collector.run() method first or verify logging")

        host_os_family = None
        for key in self.events:
            if self.events.get(key, {})[0].get("host", {}).get("id") == host_id:
                host_os_family = self.events.get(key, {})[0].get("host", {}).get("os").get("family")
                break
        if not host_os_family:
            click.echo(f"Unable to determine host.os.family for host_id: {host_id}")
            host_os_family = click.prompt(
                "Please enter the host.os.family for this host_id",
                type=click.Choice(["windows", "macos", "linux"]),
                default="windows",
            )

        dump_dir = dump_dir or self._get_dump_dir(rta_name=rta_name, host_id=host_id, host_os_family=host_os_family)

        for source, events in self.events.items():
            path = dump_dir / (source + ".ndjson")
            with path.open("w") as f:
                f.writelines([json.dumps(e, sort_keys=True) + "\n" for e in events])
                click.echo(f"{len(events)} events saved to: {path}")


class CollectEvents:
    """Event collector for elastic stack."""

    def __init__(self, client: Elasticsearch, max_events: int = 3000) -> None:
        self.client = client
        self.max_events = max_events

    def _build_timestamp_map(self, index: str) -> dict[str, Any]:
        """Build a mapping of indexes to timestamp data formats."""
        mappings = self.client.indices.get_mapping(index=index)
        return {n: m["mappings"].get("properties", {}).get("@timestamp", {}) for n, m in mappings.items()}

    def _get_last_event_time(self, index: str, dsl: dict[str, Any] | None = None) -> None | str:
        """Get timestamp of most recent event."""
        last_event = self.client.search(query=dsl, index=index, size=1, sort="@timestamp:desc")["hits"]["hits"]
        if not last_event:
            return None

        last_event = last_event[0]
        index = last_event["_index"]
        timestamp = last_event["_source"]["@timestamp"]

        timestamp_map = self._build_timestamp_map(index)
        event_date_format = timestamp_map[index].get("format", "").split("||")

        # there are many native supported date formats and even custom data formats, but most, including beats use the
        # default `strict_date_optional_time`. It would be difficult to try to account for all possible formats, so this
        # will work on the default and unix time.
        if set(event_date_format) & {"epoch_millis", "epoch_second"}:
            timestamp = unix_time_to_formatted(timestamp)

        return timestamp

    @staticmethod
    def _prep_query(
        query: str | dict[str, Any],
        language: str,
        index: str | list[str] | tuple[str],
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> tuple[str, dict[str, Any], str | None]:
        """Prep a query for search."""
        index_str = ",".join(index if isinstance(index, (list | tuple)) else index.split(","))
        lucene_query = str(query) if language == "lucene" else None

        if language in ("kql", "kuery"):
            formatted_dsl = {"query": kql.to_dsl(query)}  # type: ignore[reportUnknownMemberType]
        elif language == "eql":
            formatted_dsl = {"query": query, "filter": MATCH_ALL}
        elif language == "lucene":
            formatted_dsl: dict[str, Any] = {"query": {"bool": {"filter": []}}}
        elif language == "dsl":
            formatted_dsl = {"query": query}
        else:
            raise ValueError(f"Unknown search language: {language}")

        if start_time or end_time:
            end_time = end_time or "now"
            dsl = (
                formatted_dsl["filter"]["bool"]["filter"]
                if language == "eql"
                else formatted_dsl["query"]["bool"].setdefault("filter", [])
            )
            if not start_time:
                raise ValueError("No start time provided")

            add_range_to_dsl(dsl, start_time, end_time)

        return index_str, formatted_dsl, lucene_query

    def search(  # noqa: PLR0913
        self,
        query: str | dict[str, Any],
        language: str,
        index: str | list[str] = "*",
        start_time: str | None = None,
        end_time: str | None = None,
        size: int | None = None,
        **kwargs: Any,
    ) -> list[Any]:
        """Search an elasticsearch instance."""
        index_str, formatted_dsl, lucene_query = self._prep_query(
            query=query, language=language, index=index, start_time=start_time, end_time=end_time
        )
        formatted_dsl.update(size=size or self.max_events)

        if language == "eql":
            results = self.client.eql.search(body=formatted_dsl, index=index_str, **kwargs)["hits"]
            results = results.get("events") or results.get("sequences", [])
        else:
            results = self.client.search(
                body=formatted_dsl,
                q=lucene_query,
                index=index_str,
                allow_no_indices=True,
                ignore_unavailable=True,
                **kwargs,
            )["hits"]["hits"]

        return results

    def search_from_rule(
        self,
        rules: RuleCollection,
        start_time: str | None = None,
        end_time: str = "now",
        size: int | None = None,
    ) -> dict[str, Any]:
        """Search an elasticsearch instance using a rule."""
        async_client = AsyncSearchClient(self.client)
        survey_results: dict[str, Any] = {}
        multi_search: list[dict[str, Any]] = []
        multi_search_rules: list[TOMLRule] = []
        async_searches: list[tuple[TOMLRule, Any]] = []
        eql_searches: list[tuple[TOMLRule, dict[str, Any]]] = []

        for rule in rules:
            if not rule.contents.data.get("query"):
                continue

            language = rule.contents.data.get("language")
            query = rule.contents.data.query  # type: ignore[reportAttributeAccessIssue]
            rule_type = rule.contents.data.type
            index_str, formatted_dsl, _ = self._prep_query(
                query=query,  # type: ignore[reportUnknownArgumentType]
                language=language,  # type: ignore[reportUnknownArgumentType]
                index=rule.contents.data.get("index", "*"),  # type: ignore[reportUnknownArgumentType]
                start_time=start_time,
                end_time=end_time,
            )
            formatted_dsl.update(size=size or self.max_events)

            # prep for searches: msearch for kql | async search for lucene | eql client search for eql
            if language == "kuery":
                multi_search_rules.append(rule)
                multi_search.append({"index": index_str, "allow_no_indices": "true", "ignore_unavailable": "true"})
                multi_search.append(formatted_dsl)
            elif language == "lucene":
                # wait for 0 to try and force async with no immediate results (not guaranteed)
                result = async_client.submit(
                    body=formatted_dsl,
                    q=query,  # type: ignore[reportUnknownArgumentType]
                    index=index_str,
                    allow_no_indices=True,
                    ignore_unavailable=True,
                    wait_for_completion_timeout=0,
                )
                if result["is_running"] is True:
                    async_searches.append((rule, result["id"]))
                else:
                    survey_results[rule.id] = parse_unique_field_results(
                        rule_type, ["process.name"], result["response"]
                    )
            elif language == "eql":
                eql_body: dict[str, Any] = {
                    "index": index_str,
                    "params": {"ignore_unavailable": "true", "allow_no_indices": "true"},
                    "body": {"query": query, "filter": formatted_dsl["filter"]},
                }
                eql_searches.append((rule, eql_body))

        # assemble search results
        multi_search_results = self.client.msearch(searches=multi_search)
        for index, result in enumerate(multi_search_results["responses"]):
            try:
                rule = multi_search_rules[index]
                survey_results[rule.id] = parse_unique_field_results(
                    rule.contents.data.type,
                    rule.contents.data.unique_fields,  # type: ignore[reportAttributeAccessIssje]
                    result,
                )
            except KeyError:
                survey_results[multi_search_rules[index].id] = {"error_retrieving_results": True}

        for entry in eql_searches:
            rule, search_args = entry
            try:
                result = self.client.eql.search(**search_args)
                survey_results[rule.id] = parse_unique_field_results(
                    rule.contents.data.type,
                    rule.contents.data.unique_fields,  # type: ignore[reportAttributeAccessIssue]
                    result,  # type: ignore[reportAttributeAccessIssue]
                )
            except (elasticsearch.NotFoundError, elasticsearch.RequestError) as e:
                survey_results[rule.id] = {"error_retrieving_results": True, "error": e.info["error"]["reason"]}

        for entry in async_searches:
            rule: TOMLRule
            rule, async_id = entry
            result = async_client.get(id=async_id)["response"]
            survey_results[rule.id] = parse_unique_field_results(rule.contents.data.type, ["process.name"], result)

        return survey_results

    def count(
        self,
        query: str,
        language: str,
        index: str | list[str],
        start_time: str | None = None,
        end_time: str | None = "now",
    ) -> Any:
        """Get a count of documents from elasticsearch."""
        index_str, formatted_dsl, lucene_query = self._prep_query(
            query=query,
            language=language,
            index=index,
            start_time=start_time,
            end_time=end_time,
        )

        # EQL API has no count endpoint
        if language == "eql":
            results = self.search(
                query=query,
                language=language,
                index=index,
                start_time=start_time,
                end_time=end_time,
                size=1000,
            )
            return len(results)
        resp = self.client.count(
            body=formatted_dsl,
            index=index_str,
            q=lucene_query,
            allow_no_indices=True,
            ignore_unavailable=True,
        )

        return resp["count"]

    def count_from_rule(
        self,
        rules: RuleCollection,
        start_time: str | None = None,
        end_time: str | None = "now",
    ) -> dict[str, Any]:
        """Get a count of documents from elasticsearch using a rule."""
        survey_results: dict[str, Any] = {}

        for rule in rules.rules:
            rule_results: dict[str, Any] = {"rule_id": rule.id, "name": rule.name}

            if not rule.contents.data.get("query"):
                continue

            try:
                rule_results["search_count"] = self.count(
                    query=rule.contents.data.query,  # type: ignore[reportAttributeAccessIssue]
                    language=rule.contents.data.language,  # type: ignore[reportAttributeAccessIssue]
                    index=rule.contents.data.get("index", "*"),  # type: ignore[reportAttributeAccessIssue]
                    start_time=start_time,
                    end_time=end_time,
                )
            except (elasticsearch.NotFoundError, elasticsearch.RequestError):
                rule_results["search_count"] = -1

            survey_results[rule.id] = rule_results

        return survey_results


def evaluate(rule: TOMLRule, events: list[Any], normalize_kql_keywords: bool = False) -> list[Any]:
    """Evaluate a query against events."""
    evaluator = kql.get_evaluator(kql.parse(rule.query), normalize_kql_keywords=normalize_kql_keywords)  # type: ignore[reportUnknownMemberType]
    return list(filter(evaluator, events))  # type: ignore[reportUnknownMemberType]


def combine_sources(sources: list[Any]) -> list[Any]:
    """Combine lists of events from multiple sources."""
    combined: list[Any] = []
    for source in sources:
        combined.extend(source.copy())

    return event_sort(combined)


class CollectEventsWithDSL(CollectEvents):
    """Collect events from elasticsearch."""

    @staticmethod
    def _group_events_by_type(events: list[Any]) -> dict[str, list[Any]]:
        """Group events by agent.type."""
        event_by_type: dict[str, list[Any]] = {}

        for event in events:
            event_by_type.setdefault(event["_source"]["agent"]["type"], []).append(event["_source"])

        return event_by_type

    def run(self, dsl: dict[str, Any], indexes: str | list[str], start_time: str) -> Events:
        """Collect the events."""
        results = self.search(
            dsl,
            language="dsl",
            index=indexes,
            start_time=start_time,
            end_time="now",
            size=5000,
            sort=[{"@timestamp": {"order": "asc"}}],
        )
        events = self._group_events_by_type(results)
        return Events(events)


@root.command("normalize-data")
@click.argument("events-file", type=Path)
def normalize_data(events_file: Path) -> None:
    """Normalize Elasticsearch data timestamps and sort."""

    file_name = events_file.name
    content = events_file.read_text()
    lines = content.splitlines()

    events = Events({file_name: [json.loads(line) for line in lines]})
    events.save(dump_dir=events_file.parent)


@root.group("es")
@add_params(*elasticsearch_options)
@click.pass_context
def es_group(ctx: click.Context, **kwargs: Any) -> None:
    """Commands for integrating with Elasticsearch."""
    _ = ctx.ensure_object(dict)  # type: ignore[reportUnknownVariableType]

    # only initialize an es client if the subcommand is invoked without help (hacky)
    if sys.argv[-1] in ctx.help_option_names:
        click.echo("Elasticsearch client:")
        click.echo(format_command_options(ctx))

    else:
        ctx.obj["es"] = get_elasticsearch_client(ctx=ctx, **kwargs)


@es_group.command("collect-events")
@click.argument("host-id")
@click.option("--query", "-q", help="KQL query to scope search")
@click.option("--index", "-i", multiple=True, help="Index(es) to search against (default: all indexes)")
@click.option("--rta-name", "-r", help="Name of RTA in order to save events directly to unit tests data directory")
@click.option("--rule-id", help="Updates rule mapping in rule-mapping.yaml file (requires --rta-name)")
@click.option("--view-events", is_flag=True, help="Print events after saving")
@click.pass_context
def collect_events(  # noqa: PLR0913
    ctx: click.Context,
    host_id: str,
    query: str,
    index: list[str],
    rta_name: str,
    rule_id: str,
    view_events: bool,
) -> Events:
    """Collect events from Elasticsearch."""
    client: Elasticsearch = ctx.obj["es"]
    dsl = kql.to_dsl(query) if query else MATCH_ALL  # type: ignore[reportUnknownMemberType]
    dsl["bool"].setdefault("filter", []).append(  # type: ignore[reportUnknownMemberType]
        {
            "bool": {
                "should": [{"match_phrase": {"host.id": host_id}}],
            },
        }
    )

    try:
        collector = CollectEventsWithDSL(client)
        start = time.time()
        click.pause("Press any key once detonation is complete ...")
        start_time = f"now-{round(time.time() - start) + 5}s"
        events = collector.run(dsl, index or "*", start_time)  # type: ignore[reportUnknownArgument]
        events.save(rta_name=rta_name, host_id=host_id)

        if rta_name and rule_id:
            _ = events.evaluate_against_rule(rule_id)

        if view_events and events.events:
            events.echo_events(pager=True)

    except AssertionError as e:
        error_msg = "No events collected! Verify events are streaming and that the agent-hostname is correct"
        raise_client_error(error_msg, e, ctx=ctx)

    return events


@es_group.command("index-rules")
@click.option("--query", "-q", help="Optional KQL query to limit to specific rules")
@click.option("--from-file", "-f", type=click.File("r"), help="Load a previously saved uploadable bulk file")
@click.option("--save_files", "-s", is_flag=True, help="Optionally save the bulk request to a file")
@click.pass_context
def index_repo(ctx: click.Context, query: str, from_file: IO[Any] | None, save_files: bool) -> None:
    """Index rules based on KQL search results to an elasticsearch instance."""
    from .main import generate_rules_index

    es_client: Elasticsearch = ctx.obj["es"]

    if from_file:
        bulk_upload_docs = from_file.read()

        # light validation only
        try:
            index_body = [json.loads(line) for line in bulk_upload_docs.splitlines()]
            click.echo(f"{len([r for r in index_body if 'rule' in r])} rules included")
        except json.JSONDecodeError:
            raise_client_error(f"Improperly formatted bulk request file: {from_file.name}")
    else:
        bulk_upload_docs, _ = ctx.invoke(generate_rules_index, query=query, save_files=save_files)

    _ = es_client.bulk(operations=bulk_upload_docs)
