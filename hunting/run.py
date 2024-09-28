# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import inspect
import re
import signal
import sys
import textwrap
from pathlib import Path

import click
from tabulate import tabulate

from detection_rules.misc import get_elasticsearch_client, parse_user_config

from .utils import load_toml

# Variable to track query status for cancellation
is_running = True


def signal_handler(sig, frame):
    """Handle user interrupt for cancelling the query."""
    global is_running
    if is_running:
        click.echo("\nQuery canceled by the user.")
        sys.exit(0)


# Register signal handler for Ctrl+C to cancel the query
signal.signal(signal.SIGINT, signal_handler)


def preprocess_query(query: str) -> str:
    """Pre-process the query to remove comments and add a LIMIT if missing."""
    # Remove comments starting with '//'
    # Not allowed when using REST API
    query = re.sub(r'//.*', '', query)

    # Add LIMIT 10 if not present
    if not re.search(r'LIMIT', query, re.IGNORECASE):
        query += " | LIMIT 10"
        click.echo("No LIMIT detected in query. Added LIMIT 10 to truncate output.")

    return query


def filter_elasticsearch_params(config: dict) -> dict:
    """Filter out unwanted keys from the config by inspecting the Elasticsearch client constructor."""
    # Get the parameter names from the Elasticsearch class constructor
    es_params = inspect.signature(get_elasticsearch_client).parameters

    # Only include config keys that match the constructor parameters
    return {k: v for k, v in config.items() if k in es_params}


def send_query(file_path: Path, wait_timeout: int = 180, run_all: bool = False) -> None:
    """Run a query synchronously and check for hits, optionally running all queries."""
    global is_running

    def _format_query(query: str) -> str:
        """Format the query with word wrapping."""
        lines = query.split('\n')
        wrapped_lines = [textwrap.fill(line, width=120, subsequent_indent='    ') for line in lines]
        return '\n'.join(wrapped_lines)

    # Load the configuration
    config = parse_user_config()
    if not config:
        click.secho("No configuration found. Please add a `detection-rules-cfg` file.", fg="red", bold=True)
        return

    # Filter the config to remove unwanted parameters for Elasticsearch client
    es_config = filter_elasticsearch_params(config)

    # Load the hunting file and extract eligible queries
    hunting_data = load_toml(file_path)

    # Display description with word wrapping and color
    wrapped_description = textwrap.fill(hunting_data.description, width=120)
    click.secho("\nHunting Description:", fg="blue", bold=True)
    click.secho(f"\n{wrapped_description}\n", bold=True)

    # Extract eligible queries
    eligible_queries = {i: query for i, query in enumerate(hunting_data.query) if "from" in query}
    if not eligible_queries:
        click.secho("No eligible queries found in the file.", fg="red", bold=True)
        return

    # If `run_all` is True, run all queries
    if run_all:
        click.secho("Running all eligible queries...", fg="green", bold=True)
        for i, query in eligible_queries.items():
            click.secho(f"\nRunning Query {i + 1}:", fg="green", bold=True)
            click.echo(_format_query(query))
            run_individual_query(query, es_config, wait_timeout)
            click.secho("\n" + "-" * 120, fg="yellow")
        return

    # Output the eligible queries with separator lines
    click.secho("Available queries:", fg="blue", bold=True)
    for i, query in eligible_queries.items():
        click.secho(f"\nQuery {i + 1}:", fg="green", bold=True)
        click.echo(_format_query(query))
        click.secho("\n" + "-" * 120, fg="yellow")

    # Handle query selection
    while True:
        try:
            query_number = click.prompt("Enter the query number", type=int)
            # Adjust the query_number by subtracting 1 (because we display starting from 1)
            if query_number - 1 in eligible_queries:
                selected_query = eligible_queries[query_number - 1]
                break
            else:
                click.secho(f"Invalid query number: {query_number}. Please try again.", fg="yellow")
        except ValueError:
            click.secho("Please enter a valid number.", fg="yellow")

    # Print the selected query, preserving the format
    click.secho(f"\nSelected Query:\n", fg="blue", bold=True)
    click.echo(_format_query(selected_query))

    # Pre-process the query (e.g., remove comments, add LIMIT if necessary)
    selected_query = preprocess_query(selected_query)

    # Authenticate to the Elastic instance
    es = get_elasticsearch_client(**es_config)

    # Send query to Elasticsearch
    try:
        click.secho("Running query. Press Ctrl+C to cancel.", fg="blue")
        selected_query = selected_query.replace("\n", " ")

        # Start the query synchronously
        response = es.esql.query(query=selected_query)

        # Process results
        process_results(response)

    except Exception as e:
        click.secho(f"Error running query: {str(e)}", fg="red")


def run_individual_query(query: str, es_config: dict, wait_timeout: int):
    """Run an individual query."""
    es = get_elasticsearch_client(**es_config)

    try:
        # Pre-process the query (e.g., remove comments, add LIMIT if necessary)
        query = preprocess_query(query)

        # Removed extra log here
        query = query.replace("\n", " ")

        # Start the query synchronously
        response = es.esql.query(query=query)

        # Process results
        process_results(response)

    except Exception as e:
        click.secho(f"Error running query: {str(e)}", fg="red")


def process_results(response):
    """Process the query response and inform the user about matches."""
    global is_running
    is_running = False

    # Extract the actual data from the response object
    response_data = response.body

    # Check if there are matches
    if response_data.get('values'):
        click.secho("Query matches found!", fg="red", bold=True)
    else:
        click.secho("No matches found!", fg="green", bold=True)
