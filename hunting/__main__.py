# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import json
import textwrap
from dataclasses import asdict
from pathlib import Path

import click
from tabulate import tabulate

from detection_rules.misc import parse_user_config

from .definitions import HUNTING_DIR
from .markdown import MarkdownGenerator
from .run import QueryRunner
from .search import QueryIndex
from .utils import (filter_elasticsearch_params, get_hunt_path, load_all_toml,
                    load_toml, update_index_yml)


@click.group()
def hunting():
    """Commands for managing hunting queries and converting TOML to Markdown."""
    pass


@hunting.command('generate-markdown')
@click.argument('path', required=False)
def generate_markdown(path: click.Path):
    """Convert TOML hunting queries to Markdown format."""
    markdown_generator = MarkdownGenerator(HUNTING_DIR)

    if path:
        path = Path(path)
        if path.is_file() and path.suffix == '.toml':
            click.echo(f"Generating Markdown for single file: {path}")
            markdown_generator.process_file(path)
        elif (HUNTING_DIR / path).is_dir():
            click.echo(f"Generating Markdown for folder: {path}")
            markdown_generator.process_folder(path)
        else:
            click.echo(f"Invalid path: {path}. It should be a valid TOML file or a folder.")
    else:
        click.echo("Generating Markdown for all files.")
        markdown_generator.process_all_files()

    # After processing, update the index
    markdown_generator.update_index_md()


@hunting.command('refresh-index')
def refresh_index():
    """Refresh the index.yml file from TOML files and then refresh the index.md file."""
    click.echo("Refreshing the index.yml and index.md files.")
    update_index_yml(HUNTING_DIR)
    markdown_generator = MarkdownGenerator(HUNTING_DIR)
    markdown_generator.update_index_md()
    click.echo("Index refresh complete.")


@hunting.command('search')
@click.option('--tactic', type=str, default=None, help="Search by MITRE tactic ID (e.g., TA0001)")
@click.option('--technique', type=str, default=None, help="Search by MITRE technique ID (e.g., T1078)")
@click.option('--sub-technique', type=str, default=None, help="Search by MITRE sub-technique ID (e.g., T1078.001)")
@click.option('--data-source', type=str, default=None, help="Filter by data_source like 'aws', 'macos', or 'linux'")
@click.option('--keyword', type=str, default=None, help="Search by keyword in name, description, and notes")
def search_queries(tactic: str, technique: str, sub_technique: str, data_source: str, keyword: str):
    """Search for queries based on MITRE tactic, technique, sub-technique, or data_source."""

    if not any([tactic, technique, sub_technique, data_source, keyword]):
        raise click.UsageError("""Please provide at least one filter (tactic, technique, sub-technique,
                               data_source or keyword) to search queries.""")

    click.echo("Searching for queries based on provided filters...")

    # Create an instance of the QueryIndex class
    query_index = QueryIndex(HUNTING_DIR)

    # Filter out None values from the MITRE filter tuple
    mitre_filters = tuple(filter(None, (tactic, technique, sub_technique)))

    # Call the search method of QueryIndex with the provided MITRE filters, data_source, and keyword
    results = query_index.search(mitre_filter=mitre_filters, data_source=data_source, keyword=keyword)

    if results:
        click.secho(f"\nFound {len(results)} matching queries:\n", fg="green", bold=True)

        # Prepare the data for tabulate
        table_data = []
        for result in results:
            # Customize output to include technique, data_source, and UUID
            data_source_str = result['data_source']
            mitre_str = ", ".join(result['mitre'])
            uuid = result['uuid']
            table_data.append([result['name'], uuid, result['path'], data_source_str, mitre_str])

        # Output results using tabulate
        table_headers = ["Name", "UUID", "Location", "Data Source", "MITRE"]
        click.echo(tabulate(table_data, headers=table_headers, tablefmt="fancy_grid"))

    else:
        click.secho("No matching queries found.", fg="red", bold=True)


@hunting.command('view-hunt')
@click.option('--uuid', type=str, help="View a specific hunt by UUID.")
@click.option('--path', type=str, help="View a specific hunt by file path.")
@click.option('--format', 'output_format', default='toml', type=click.Choice(['toml', 'json'], case_sensitive=False),
              help="Output format (toml or json).")
@click.option('--query-only', is_flag=True, help="Only display the query content.")
def view_hunt(uuid: str, path: str, output_format: str, query_only: bool):
    """View a specific hunt by UUID or file path in the specified format (TOML or JSON)."""

    # Get the hunt path or error message
    hunt_path, error_message = get_hunt_path(uuid, path)

    if error_message:
        click.secho(f"{error_message}", fg="red", bold=True)
        return

    # Load the TOML data
    hunt = load_toml(hunt_path)

    # Handle query-only option
    if query_only:
        click.secho("Available queries:", fg="blue", bold=True)
        # Format queries for display using tabulate and textwrap
        table_data = [(i, textwrap.fill(query, width=120)) for i, query in enumerate(hunt.query)]
        table_headers = ["Query"]
        click.echo(tabulate(table_data, headers=table_headers, tablefmt="fancy_grid"))
        return

    # Output the hunt in the requested format
    if output_format == 'toml':
        click.echo(hunt_path.read_text())
    elif output_format == 'json':
        hunt_dict = asdict(hunt)
        click.echo(json.dumps(hunt_dict, indent=4))


@hunting.command('hunt-summary')
@click.option('--breakdown', type=click.Choice(['platform', 'integration', 'language'],
                                               case_sensitive=False), default='platform',
              help="Specify how to break down the summary: 'platform', 'integration', or 'language'.")
def hunt_summary(breakdown: str):
    """
    Generate a summary of hunt queries, broken down by platform, integration, or language.
    """
    click.echo(f"Generating hunt summary broken down by {breakdown}...")

    # Load all hunt queries
    all_hunts = load_all_toml(HUNTING_DIR)

    # Prepare data structures for summary
    platform_summary = {}
    integration_summary = {}
    language_summary = {}

    for hunt, path in all_hunts:
        # Get the platform based on the folder name
        platform = path.parent.parent.stem

        # Extract integrations and languages used in the query
        integrations = hunt.integration
        languages = hunt.language

        # Update platform-based summary
        if platform not in platform_summary:
            platform_summary[platform] = 0
        platform_summary[platform] += 1

        # Update integration-based summary
        for integration in integrations:
            if integration not in integration_summary:
                integration_summary[integration] = 0
            integration_summary[integration] += 1

        # Update language-based summary
        for language in languages:
            if language == 'SQL':
                language = 'OSQuery'
            if language not in language_summary:
                language_summary[language] = 0
            language_summary[language] += 1

    # Prepare and display the table based on the selected breakdown
    if breakdown == 'platform':
        # Create a table for the platform breakdown
        table_data = [[platform, count] for platform, count in platform_summary.items()]
        table_headers = ["Platform (Folder)", "Hunt Count"]
        click.echo(tabulate(table_data, headers=table_headers, tablefmt="fancy_grid"))

    elif breakdown == 'integration':
        # Create a table for the integration breakdown
        table_data = [[integration, count] for integration, count in integration_summary.items()]
        table_headers = ["Integration", "Hunt Count"]
        click.echo(tabulate(table_data, headers=table_headers, tablefmt="fancy_grid"))

    elif breakdown == 'language':
        # Create a table for the language breakdown
        table_data = [[language, count] for language, count in language_summary.items()]
        table_headers = ["Language", "Hunt Count"]
        click.echo(tabulate(table_data, headers=table_headers, tablefmt="fancy_grid"))


@hunting.command('run-query')
@click.option('--uuid', help="The UUID of the hunting query to run.")
@click.option('--file-path', help="The file path of the hunting query to run.")
@click.option('--all', 'run_all', is_flag=True, help="Run all eligible queries in the file.")
@click.option('--wait-time', 'wait_time', default=180, help="Time to wait for query completion.")
def run_query(uuid: str, file_path: str, run_all: bool, wait_time: int):
    """Run a hunting query by UUID or file path. Only ES|QL queries are supported."""

    # Get the hunt path or error message
    hunt_path, error_message = get_hunt_path(uuid, file_path)

    if error_message:
        click.echo(error_message)
        return

    # Load the user configuration
    config = parse_user_config()
    if not config:
        click.secho("No configuration found. Please add a `detection-rules-cfg` file.", fg="red", bold=True)
        return

    es_config = filter_elasticsearch_params(config)

    # Create a QueryRunner instance
    query_runner = QueryRunner(es_config)

    # Load the hunting data
    hunting_data = query_runner.load_hunting_file(hunt_path)

    # Display description
    wrapped_description = textwrap.fill(hunting_data.description, width=120)
    click.secho("\nHunting Description:", fg="blue", bold=True)
    click.secho(f"\n{wrapped_description}\n", bold=True)

    # Extract eligible queries
    eligible_queries = {i: query for i, query in enumerate(hunting_data.query) if "from" in query}
    if not eligible_queries:
        click.secho("No eligible queries found in the file.", fg="red", bold=True)
        return

    if run_all:
        # Run all eligible queries if the --all flag is set
        query_runner.run_all_queries(eligible_queries, wait_time)
        return

    # Display available queries
    click.secho("Available queries:", fg="blue", bold=True)
    for i, query in eligible_queries.items():
        click.secho(f"\nQuery {i + 1}:", fg="green", bold=True)
        click.echo(query_runner._format_query(query))
        click.secho("\n" + "-" * 120, fg="yellow")

    # Handle query selection
    while True:
        try:
            query_number = click.prompt("Enter the query number", type=int)
            if query_number - 1 in eligible_queries:
                selected_query = eligible_queries[query_number - 1]
                break
            else:
                click.secho(f"Invalid query number: {query_number}. Please try again.", fg="yellow")
        except ValueError:
            click.secho("Please enter a valid number.", fg="yellow")

    # Run the selected query
    query_runner.run_individual_query(selected_query, wait_time)


if __name__ == "__main__":
    hunting()
