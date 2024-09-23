# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path

import click

from .definitions import HUNTING_DIR
from .markdown import process_toml_files, update_index_md
from .run import send_query
from .search import search_index
from .utils import load_index_file, update_index_yml


@click.group()
def hunting():
    """Commands for managing hunting queries and converting TOML to Markdown."""
    pass


@hunting.command('generate-markdown')
@click.argument('path', required=False)
def generate_markdown(path):
    """Convert TOML hunting queries to Markdown format.

    The 'path' argument can be:
    - A specific TOML file,
    - A folder (e.g., "aws") to process all TOML files in that subfolder,
    - Or if no path is provided, all TOML files in the base path and subfolders will be processed.

    Markdown files will be saved in the respective docs folder.
    The hunting/index.md and index.yml file will be updated.
    """
    if path:
        path = Path(path)

        if path.is_file() and path.suffix == '.toml':
            click.echo(f"Generating Markdown for single file: {path}")
            process_toml_files(HUNTING_DIR, file_path=path)
        elif (HUNTING_DIR / path).is_dir():
            click.echo(f"Generating Markdown for folder: {path}")
            process_toml_files(HUNTING_DIR, folder=path)
        else:
            click.echo(f"Invalid path: {path}. It should be a valid TOML file or a folder.")
    else:
        click.echo("Generating Markdown for all files.")
        process_toml_files(HUNTING_DIR)


@hunting.command('refresh-index')
def refresh_index():
    """Refresh the index.yml file from TOML files and then refresh the index.md file."""
    click.echo("Refreshing the index.yml and index.md files.")
    update_index_yml(HUNTING_DIR)
    update_index_md(HUNTING_DIR)
    click.echo("Index refresh complete.")


@hunting.command('search')
@click.option('--tactic', type=str, default=None, help="Search by MITRE tactic ID (e.g., TA0001)")
@click.option('--technique', type=str, default=None, help="Search by MITRE technique ID (e.g., T1078)")
@click.option('--sub-technique', type=str, default=None, help="Search by MITRE sub-technique ID (e.g., T1078.001)")
@click.option('--data-source', type=str, default=None, help="Filter by data_source like 'aws', 'macos', or 'linux'")
def search_queries(tactic: str, technique: str, sub_technique: str, data_source: str):
    """Search for queries based on MITRE tactic, technique, sub-technique, or data_source."""

    if not any([tactic, technique, sub_technique, data_source]):
        raise click.UsageError("""Please provide at least one filter (tactic, technique, sub-technique,
                               or data_source) to search queries.""")

    click.echo("Searching for queries based on provided filters...")

    # Filter out None values from the MITRE filter tuple
    mitre_filters = tuple(filter(None, (tactic, technique, sub_technique)))

    # Call search_index with the provided MITRE filters and data_source
    results = search_index(HUNTING_DIR, mitre_filter=mitre_filters, data_source=data_source)

    if results:
        click.echo(f"\nFound {len(results)} matching queries:\n")
        for result in results:
            # Customize output to include technique and data_source if available
            data_source_str = result.get('data_source', 'Unknown')
            mitre_str = ", ".join(result.get('mitre', [])) or 'No MITRE techniques'
            click.echo(f"- {result['name']} | location: ({result['path']}) | data_source: {data_source_str} | MITRE: {mitre_str}")  # noqa: E501
    else:
        click.echo("No matching queries found.")

@hunting.command('view-hunt')
@click.option('--uuid', type=str, help="View a specific hunt by UUID.")
@click.option('--path', type=str, help="View a specific hunt by file path.")
@click.option('--format', 'output_format', default='toml', type=click.Choice(['toml', 'json'], case_sensitive=False),
              help="Output format (toml or json).")
def view_hunt(uuid: str, path: str, output_format: str):
    """View a specific hunt by UUID or file path in the specified format (TOML or JSON)."""

    # Load index.yml if UUID is provided
    if uuid:
        index_data = load_index_file()
        hunt_data = None
        for data_source, hunts in index_data.items():
            if uuid in hunts:
                hunt_data = hunts[uuid]
                hunt_path = Path(HUNTING_DIR) / hunt_data['path']
                break

        if not hunt_data:
            click.echo(f"No hunt found for UUID: {uuid}")
            return
    # If path is provided
    elif path:
        hunt_path = Path(path)
        if not hunt_path.is_file():
            click.echo(f"No file found at path: {path}")
            return
    else:
        click.echo("Please provide either a UUID or a file path.")
        return

    # Load the TOML data
    hunt = load_toml(hunt_path)

    # Output the hunt in the requested format
    if output_format == 'toml':
        click.echo(hunt_path.read_text())
    elif output_format == 'json':
        import json
        hunt_dict = hunt.__dict__  # Convert the dataclass to a dictionary
        click.echo(json.dumps(hunt_dict, indent=4))


@hunting.command('run-query')
@click.option('--uuid', help="The UUID of the hunting query to run.")
@click.option('--file-path', help="The file path of the hunting query to run.")
@click.option('--output-format', 'output_format', default='json',
              type=click.Choice(['json', 'csv', 'txt', 'yaml', 'tsv', 'txt']),
              help="Output format (json, csv, txt, yaml, tsv). Default is json.")
@click.option('--wait-time', default=180, help="Time in seconds to wait for query completion. Default is 180 seconds.")
def run_query(uuid: str, file_path: str, output_format: str, wait_time: int):
    """Run a hunting query by UUID or file path. Only ES|QL queries are supported."""
    if not any([uuid, file_path]):
        raise click.UsageError("Please provide either a UUID or a file path to run a query.")

    if uuid:
        hunt_path = None
        index_data = load_index_file()
        for data_source, hunts in index_data.items():
            if uuid in hunts:
                hunt_data = hunts[uuid]
                hunt_path = Path(HUNTING_DIR) / hunt_data['path']
                break

        if not hunt_path:
            click.echo(f"No hunt found for UUID: {uuid}")
            return
    elif file_path:
        hunt_path = Path(file_path)
        if not hunt_path.is_file():
            click.echo(f"No file found at path: {file_path}")
            return

    # Run the query
    send_query(hunt_path, output_format, wait_time)


if __name__ == "__main__":
    hunting()

