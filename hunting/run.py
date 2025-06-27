# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import re
import textwrap
from pathlib import Path
from typing import Any

import click

from detection_rules.misc import get_elasticsearch_client

from .definitions import Hunt
from .utils import load_toml


class QueryRunner:
    def __init__(self, es_config: dict[str, Any]) -> None:
        """Initialize the QueryRunner with Elasticsearch config."""
        self.es_config = es_config

    def load_hunting_file(self, file_path: Path) -> Hunt:
        """Load the hunting file and return the data."""
        return load_toml(file_path)

    def preprocess_query(self, query: str) -> str:
        """Pre-process the query by removing comments and adding a LIMIT."""
        query = re.sub(r"//.*", "", query)
        if not re.search(r"LIMIT", query, re.IGNORECASE):
            query += " | LIMIT 10"
            click.echo("No LIMIT detected in query. Added LIMIT 10 to truncate output.")
        return query

    def run_individual_query(self, query: str, _: int) -> None:
        """Run a single query with the Elasticsearch config."""
        es = get_elasticsearch_client(**self.es_config)
        query = self.preprocess_query(query)

        try:
            click.secho("Running query. Press Ctrl+C to cancel.", fg="blue")
            query = query.replace("\n", " ")

            # Start the query synchronously
            response = es.esql.query(query=query)

            response_data = response.body
            if response_data.get("values"):
                click.secho("Query matches found!", fg="red", bold=True)
            else:
                click.secho("No matches found!", fg="green", bold=True)

        except Exception as e:  # noqa: BLE001
            # handle missing index error
            if "Unknown index" in str(e):
                click.secho("This query references indexes that do not exist in the target stack.", fg="red")
                click.secho("Check if index exists (via integration installation) and contains data.", fg="red")
                click.secho("Alternatively, update the query to reference an existing index.", fg="red")
            else:
                click.secho(f"Error running query: {e!s}", fg="red")

    def run_all_queries(self, queries: dict[int, Any], wait_timeout: int) -> None:
        """Run all eligible queries in the hunting file."""
        click.secho("Running all eligible queries...", fg="green", bold=True)
        for i, query in queries.items():
            click.secho(f"\nRunning Query {i + 1}:", fg="green", bold=True)
            click.echo(self.format_query(query))
            self.run_individual_query(query, wait_timeout)
            click.secho("\n" + "-" * 120, fg="yellow")

    def format_query(self, query: str) -> str:
        """Format the query with word wrapping for better readability."""
        lines = query.split("\n")
        wrapped_lines = [textwrap.fill(line, width=120, subsequent_indent="    ") for line in lines]
        return "\n".join(wrapped_lines)
