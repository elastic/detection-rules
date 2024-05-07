# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Commands for supporting custom rules."""
from pathlib import Path

import click
import yaml

from .main import root
from .utils import get_etc_path

DEFAULT_CONFIG_PATH = Path(get_etc_path('_config.yaml'))


@root.group('custom-rules')
def custom_rules():
    """Commands for supporting custom rules."""


def create_config_content(use_defaults: bool, etc_dir: Path) -> str:
    """Create the content for the _config.yaml file."""
    # Base structure of the configuration
    config_content = {
        'rule_dirs': ['rules', 'rules_building_block'],
        'files': {
            'deprecated_rules': 'etc/deprecated_rules.json',
            'packages': 'etc/packages.yml',
            'stack_schema_map': 'etc/stack-schema-map.yaml',
            'version_lock': 'etc/version.lock.json',
        },
        'testing': {
            'config': 'etc/test_config.yaml'
        }
    }

    if not use_defaults:
        # Add detailed configuration instructions
        config_content = {
            'configuration_details': (
                f'# For details on how to configure this file,\n'
                f'# consult: {DEFAULT_CONFIG_PATH.resolve()}\n'
                f'# or the docs: {etc_dir.parent.parent / "docs" / "custom-rules.md"}\n'
                f'# Optionally use the `--use-defaults` flag to get started.'
            )
        }

    click.echo(f'Configured _config.yaml with{" default contents" if use_defaults else " detailed instructions"}')
    return yaml.safe_dump(config_content, default_flow_style=False)


@custom_rules.command('init-config')
@click.argument('directory', type=Path)
@click.option('--use-defaults', is_flag=True, help="Use default contents from detection_rules/etc folder.")
def init_config(directory: Path, use_defaults: bool):
    """Initialize the custom rules configuration."""
    etc_dir = directory / 'etc'
    config = directory / '_config.yaml'
    directories = [
        directory / 'actions',
        directory / 'exceptions',
        directory / 'rules',
        directory / 'rules_building_block',
        etc_dir,
    ]
    files = [
        etc_dir / 'deprecated_rules.json',
        etc_dir / 'packages.yml',
        etc_dir / 'stack-schema-map.yaml',
        etc_dir / 'version.lock.json',
        etc_dir / 'test_config.yaml',
    ]

    # Create directories
    for dir_ in directories:
        dir_.mkdir(parents=True, exist_ok=True)
        click.echo(f'Created directory: {dir_}')

    # Create files and populate with default content if applicable
    for file_ in files:
        content_to_write = '{}'
        if use_defaults and file_.name in [
            'packages.yml',
            'stack-schema-map.yaml',
            'test_config.yaml',
        ]:
            default_path = "example_test_config.yaml" if file_.name == "test_config.yaml" else file_.name
            default_content = DEFAULT_CONFIG_PATH.parent.joinpath(default_path).read_text()
            content_to_write = default_content
        file_.write_text(content_to_write)
        click.echo(
            f'Created file with default content: {file_}' if use_defaults else f'Created file: {file_}'
        )

    # Create and configure _config.yaml
    config.write_text(create_config_content(use_defaults, etc_dir))
