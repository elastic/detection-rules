# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path

import click

from hunting.definitions import HUNTING_DIR
from hunting.markdown import (process_toml_files, update_index_file,
                              update_index_yml)
from hunting.utils import search_index


@click.group()
def hunting():
    """Commands for managing hunting queries and converting TOML to Markdown."""
    pass


@hunting.command('generate-markdown')
@click.argument('path', required=False, description="Path to TOML file or folder to generate Markdown files.")
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
    update_index_file(HUNTING_DIR)
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
            click.echo(f"- {result['name']} | UUID: {result['uuid']} | location: ({result['path']}) | data_source: {data_source_str} | MITRE: {mitre_str}")  # noqa: E501
    else:
        click.echo("No matching queries found.")


if __name__ == "__main__":
    hunting()
