# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Commands for supporting custom rules."""
from pathlib import Path

import click

from .main import root
from .utils import get_etc_path


DEFAULT_CONFIG_PATH = Path(get_etc_path('_config.yaml'))


@root.group('custom-rules')
def custom_rules():
    """Commands for supporting custom rules."""


@custom_rules.command('init-config')
@click.argument('directory', type=Path)
def init_config(directory: Path):
    """Initialize the custom rules configuration."""
    etc_dir = directory / 'etc'
    config = directory / '_config.yaml'
    directories = [
        directory / 'actions',
        directory / 'exceptions',
        directory / 'rules',
        etc_dir
    ]
    files = [
        config,
        etc_dir / 'deprecated_rules.json',
        etc_dir / 'packages.yml',
        etc_dir / 'stack-schema-map.yml',
        etc_dir / 'version.lock.json',
        etc_dir / 'test_config.yaml',
    ]
    for dir_ in directories:
        dir_.mkdir(parents=True, exist_ok=True)
        click.echo(f'created directory: {dir_}')
    for file_ in files:
        file_.write_text('{}')
        click.echo(f'created file: {file_}')
    config.write_text(f'# for details on how to configure this file, consult: {DEFAULT_CONFIG_PATH.resolve()} or docs')
