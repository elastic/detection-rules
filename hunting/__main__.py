# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path

import click

from hunting.definitions import HUNTING_DIR
from hunting.markdown import process_toml_files, update_index_file


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
    """Refresh the index.md file based on the current contents of index.yml."""
    click.echo("Refreshing the index.md file based on index.yml")
    update_index_file(HUNTING_DIR)
    click.echo("Index has been refreshed successfully.")

if __name__ == "__main__":
    hunting()
