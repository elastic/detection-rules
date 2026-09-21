# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ESQL Query Parsing Classes."""

import re
from dataclasses import dataclass

from .schemas.definitions import (
    ESQL_COMMENTS_AND_LITERALS_REGEX,
    ESQL_FROM_KEYWORD_REGEX,
    ESQL_FROM_SOURCES_TERMINATOR_REGEX,
    ESQL_INDEX_PATTERN_REGEX,
)


@dataclass
class EventDataset:
    """Dataclass for event.dataset with integration and datastream parts."""

    package: str
    integration: str

    def __str__(self) -> str:
        return f"{self.package}.{self.integration}"


@dataclass
class EsqlSourceGroup:
    """Dataclass for the FROM clauses of a query that read the same index patterns."""

    indices: list[str]
    spans: list[tuple[int, int]]


def get_esql_query_event_dataset_integrations(query: str) -> list[EventDataset]:
    """Extract event.dataset and data_stream.dataset integrations from an ES|QL query."""
    number_of_parts = 2
    # Regex patterns for event.dataset, and data_stream.dataset
    # This mimics the logic in get_datasets_and_modules but for ES|QL as we do not have an ast

    regex_patterns = {
        "in": [
            re.compile(r"event\.dataset\s+in\s*\(\s*([^)]+)\s*\)"),
            re.compile(r"data_stream\.dataset\s+in\s*\(\s*([^)]+)\s*\)"),
        ],
        "eq": [
            re.compile(r'event\.dataset\s*==\s*"([^"]+)"'),
            re.compile(r'data_stream\.dataset\s*==\s*"([^"]+)"'),
        ],
    }

    # Extract datasets
    datasets: list[str] = []
    for regex_list in regex_patterns.values():
        for regex in regex_list:
            matches = regex.findall(query)
            if matches:
                for match in matches:
                    if "," in match:
                        # Handle `in` case with multiple values
                        datasets.extend([ds.strip().strip('"') for ds in match.split(",")])
                    else:
                        # Handle `==` case
                        datasets.append(match.strip().strip('"'))

    event_datasets: list[EventDataset] = []
    for dataset in datasets:
        parts = dataset.split(".")
        if len(parts) == number_of_parts:  # Ensure there are exactly two parts
            event_datasets.append(EventDataset(package=parts[0], integration=parts[1]))

    return event_datasets


def split_esql_source_list(sources: str) -> list[str]:
    """Split a FROM clause source list into its local index patterns."""
    indices: list[str] = []
    for source in sources.split(","):
        # Truncate cross cluster search indices to local indices
        index = source.split(":", 1)[-1].strip()
        if ESQL_INDEX_PATTERN_REGEX.match(index):
            indices.append(index)
    return indices


def get_esql_query_source_groups(query: str) -> list[EsqlSourceGroup]:
    """Group the FROM clauses of an ES|QL query by the index patterns they read."""

    def blank(match: re.Match[str]) -> str:
        return "".join("\n" if char == "\n" else " " for char in match.group(0))

    # Blanked in place, preserving offsets, so that the FROM keyword or something shaped like an
    # index pattern is never read out of a comment or a query value
    scannable = ESQL_COMMENTS_AND_LITERALS_REGEX.sub(blank, query)

    groups: dict[tuple[str, ...], EsqlSourceGroup] = {}
    for match in ESQL_FROM_KEYWORD_REGEX.finditer(scannable):
        start = match.end()
        # The outer FROM of a subquery union takes subqueries rather than index patterns,
        # so it has no source list of its own and only each subquery's FROM clause is grouped
        if scannable[start:].lstrip().startswith("("):
            continue
        terminator = ESQL_FROM_SOURCES_TERMINATOR_REGEX.search(scannable, start)
        end = terminator.start() if terminator else len(scannable)
        sources = scannable[start:end]
        indices = split_esql_source_list(sources)
        # Guards against a FROM keyword that is part of an expression rather than a source clause
        if not indices:
            continue
        # Clauses reading the same sources share a group, so they also share prepared test indices
        group = groups.setdefault(tuple(indices), EsqlSourceGroup(indices=indices, spans=[]))
        group.spans.append((start, start + len(sources.rstrip())))

    return list(groups.values())


def get_esql_query_indices(query: str) -> list[str]:
    """Extract the unique index patterns from every FROM clause in an ES|QL query."""
    indices: list[str] = []
    for group in get_esql_query_source_groups(query):
        for index in group.indices:
            if index not in indices:
                indices.append(index)
    return indices


def replace_esql_query_sources(query: str, replacements: dict[tuple[int, int], str]) -> str:
    """Replace each FROM clause source list with the index string mapped to its span."""
    # Applied back to front so that earlier spans keep their offsets
    for (start, end), replacement in sorted(replacements.items(), reverse=True):
        query = query[:start] + replacement + query[end:]
    return query
