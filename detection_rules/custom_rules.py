# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Commands for supporting custom rules."""
from pathlib import Path

import click
import yaml

from .main import root
from .utils import get_etc_path, load_etc_dump, ROOT_DIR

from semver import Version

DEFAULT_CONFIG_PATH = Path(get_etc_path('_config.yaml'))
CUSTOM_RULES_DOC_PATH = Path(ROOT_DIR).joinpath('docs', 'custom-rules.md')


@root.group('custom-rules')
def custom_rules():
    """Commands for supporting custom rules."""


def create_config_content() -> str:
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

    return yaml.safe_dump(config_content, default_flow_style=False)


def create_test_config_content() -> str:
    """Generate the content for the test_config.yaml with special content and references."""
    example_test_config_path = DEFAULT_CONFIG_PATH.parent.joinpath("example_test_config.yaml")
    content = f"# For more details, refer to the example configuration:\n# {example_test_config_path}\n" \
              "# Define tests to explicitly bypass, with all others being run.\n" \
              "# To run all tests, set bypass to empty or leave this file commented out.\n\n" \
              "unit_tests:\n  bypass:\n#  - tests.test_all_rules.TestValidRules.test_schema_and_dupes\n" \
              "#  - tests.test_packages.TestRegistryPackage.test_registry_package_config\n"

    return content


@custom_rules.command('setup-config')
@click.argument('directory', type=Path)
@click.argument('kibana-version', type=str, default=load_etc_dump('packages.yml')['package']['name'])
@click.option('--overwrite', is_flag=True, help="Overwrite the existing _config.yaml file.")
def setup_config(directory: Path, kibana_version: str, overwrite: bool):
    """Setup the custom rules configuration directory and files with defaults."""

    config = directory / '_config.yaml'
    if not overwrite and config.exists():
        raise FileExistsError(f'{config} already exists. Use --overwrite to update')

    etc_dir = directory / 'etc'
    test_config = etc_dir / 'test_config.yaml'
    package_config = etc_dir / 'packages.yml'
    stack_schema_map_config = etc_dir / 'stack-schema-map.yaml'
    config_files = [
        package_config,
        stack_schema_map_config,
        test_config,
        config,
    ]
    directories = [
        directory / 'actions',
        directory / 'exceptions',
        directory / 'rules',
        directory / 'rules_building_block',
        etc_dir,
    ]
    version_files = [
        etc_dir / 'deprecated_rules.json',
        etc_dir / 'version.lock.json',
    ]

    # Create directories
    for dir_ in directories:
        dir_.mkdir(parents=True, exist_ok=True)
        click.echo(f'Created directory: {dir_}')

    # Create version_files and populate with default content if applicable
    for file_ in version_files:
        file_.write_text('{}')
        click.echo(
            f'Created file with default content: {file_}'
        )

    # Create the stack-schema-map.yaml file
    stack_schema_map_content = load_etc_dump('stack-schema-map.yaml')
    latest_version = max(stack_schema_map_content.keys(), key=lambda v: Version.parse(v))
    latest_entry = {latest_version: stack_schema_map_content[latest_version]}
    stack_schema_map_config.write_text(yaml.safe_dump(latest_entry, default_flow_style=False))

    # Create default packages.yml
    package_content = {'package': {'name': kibana_version}}
    package_config.write_text(yaml.safe_dump(package_content, default_flow_style=False))

    # Create and configure test_config.yaml
    test_config.write_text(create_test_config_content())

    # Create and configure _config.yaml
    config.write_text(create_config_content())

    for file_ in config_files:
        click.echo(f'Created file with default content: {file_}')

    click.echo(f'\n# For details on how to configure the _config.yaml file,\n'
               f'# consult: {DEFAULT_CONFIG_PATH.resolve()}\n'
               f'# or the docs: {CUSTOM_RULES_DOC_PATH.resolve()}')
