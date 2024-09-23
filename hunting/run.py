# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path
import click
import signal
import sys
from detection_rules.misc import parse_user_config, get_elasticsearch_client
from .utils import load_toml
from tabulate import tabulate
import time

# Variable to track query status for cancellation
query_id = None
is_running = True

def signal_handler(sig, frame):
    """Handle user interrupt for cancelling the query."""
    global query_id, is_running
    if is_running and query_id:
        click.echo("\nCancelling the query...")
        es = get_elasticsearch_client(**parse_user_config())
        try:
            es.esql.async_query_delete(id=query_id)
            click.echo(f"Query {query_id} cancelled successfully.")
        except Exception as e:
            click.echo(f"Failed to cancel the query: {str(e)}")
    sys.exit(0)

# Register signal handler for Ctrl+C
signal.signal(signal.SIGINT, signal_handler)

def send_query(file_path: Path, output_format: str, wait_timeout: int = 180) -> None:
    """Run a query asynchronously and handle export options."""
    global query_id, is_running

    # Load the configuration
    config = parse_user_config()
    if not config:
        click.echo("No configuration found. Please add a `detection-rules-cfg` file.")
        return

    # Load the hunting file and extract eligible queries
    hunting_data = load_toml(file_path)
    eligible_queries = {i: query for i, query in enumerate(hunting_data.query) if "from" in query}

    if not eligible_queries:
        click.echo("No eligible queries found in the file.")
        return

    # Prepare the data for tabulated display
    table_data = [(i, query) for i, query in eligible_queries.items()]
    table_headers = ["Number", "Query"]

    # Output the eligible queries using tabulate
    click.echo(tabulate(table_data, headers=table_headers, tablefmt="fancy_grid"))

    # Handle query selection
    while True:
        query_number = click.prompt("Enter the query number", type=int)
        if query_number in eligible_queries:
            selected_query = eligible_queries[query_number]
            break
        else:
            click.echo(f"Invalid query number: {query_number}. Please try again.")

    # Authenticate to the Elastic instance
    es = get_elasticsearch_client(**config)

    # Start the async query
    try:
        click.echo(f"Running query with a wait time of {wait_timeout}s. Press Ctrl+C to cancel.")
        response = es.esql.async_query(
            body={
                "query": selected_query,
                "wait_for_completion_timeout": f"{wait_timeout}s"
            }
        )

        # Check if the query is still running and extract query ID
        query_id = response.get('id')
        is_running = response.get('is_running', False)

        if is_running:
            click.echo(f"Query {query_id} is still running in the background.")
        else:
            process_results(response, output_format)

    except Exception as e:
        click.echo(f"Error running query: {str(e)}")

def process_results(response, output_format):
    """Process and display query results."""
    global is_running
    is_running = False  # Query has finished

    # Process the result and display it in the desired format
    if output_format == 'json':
        click.echo(response)
    else:
        # Convert to tabular format or desired output format
        headers = [col['name'] for col in response['columns']]
        values = response['values']
        if output_format in ['txt', 'csv', 'tsv']:
            click.echo(tabulate(values, headers=headers, tablefmt=output_format))
        elif output_format == 'yaml':
            click.echo(yaml.safe_dump(response))

    # Export results if needed
    export_to_file = click.prompt("Would you like to export the results to a file? (y/n)", default='n')
    if export_to_file.lower() == 'y':
        export_file = click.prompt("Enter the filename to export")
        with open(export_file, 'w', encoding='utf-8') as file:
            if output_format == 'json':
                file.write(str(response))
            else:
                file.write(tabulate(values, headers=headers, tablefmt=output_format))
        click.echo(f"Results exported to {export_file}")