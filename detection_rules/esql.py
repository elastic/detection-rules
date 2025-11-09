# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ESQL Query Parsing Classes."""

import re
from dataclasses import dataclass


@dataclass
class EventDataset:
    """Dataclass for event.dataset with integration and datastream parts."""

    package: str
    integration: str

    def __str__(self) -> str:
        return f"{self.package}.{self.integration}"


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
