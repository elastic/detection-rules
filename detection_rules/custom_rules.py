# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Commands for supporting custom rules."""

from pathlib import Path

import click
import yaml
from semver import Version

from .docs import REPO_DOCS_DIR
from .main import root
from .utils import ROOT_DIR, get_etc_path, load_etc_dump

DEFAULT_CONFIG_PATH = Path(get_etc_path(["_config.yaml"]))
CUSTOM_RULES_DOC_PATH = ROOT_DIR / REPO_DOCS_DIR / "custom-rules-management.md"


@root.group("custom-rules")
def custom_rules() -> None:
    """Commands for supporting custom rules."""


def create_config_content() -> str:
    """Create the initial content for the _config.yaml file."""
    # Base structure of the configuration
    config_content = {
        "rule_dirs": ["rules"],
        "bbr_rules_dirs": ["rules_building_block"],
        "directories": {
            "action_dir": "actions",
            "action_connector_dir": "action_connectors",
            "exception_dir": "exceptions",
        },
        "files": {
            "deprecated_rules": "etc/deprecated_rules.json",
            "packages": "etc/packages.yaml",
            "stack_schema_map": "etc/stack-schema-map.yaml",
            "version_lock": "etc/version.lock.json",
        },
        "testing": {"config": "etc/test_config.yaml"},
    }

    return yaml.safe_dump(config_content, default_flow_style=False)


def create_test_config_content(enable_prebuilt_tests: bool) -> str:
    """Generate the content for the test_config.yaml with special content and references."""

    def format_test_string(test_string: str, comment_char: str) -> str:
        """Generate a yaml formatted string with a comment character."""
        return f"{comment_char}  - {test_string}"

    comment_char = "#" if enable_prebuilt_tests else ""
    example_test_config_path = DEFAULT_CONFIG_PATH.parent.joinpath("example_test_config.yaml")

    lines = [
        "# For more details, refer to the example configuration:",
        f"# {example_test_config_path}",
        "# Define tests to explicitly bypass, with all others being run.",
        "# To run all tests, set bypass to empty or leave this file commented out.",
        "",
        "unit_tests:",
        "  bypass:",
        format_test_string("tests.test_gh_workflows.TestWorkflows.test_matrix_to_lock_version_defaults", comment_char),
        format_test_string(
            "tests.test_schemas.TestVersionLockSchema.test_version_lock_has_nested_previous", comment_char
        ),
        format_test_string("tests.test_packages.TestRegistryPackage.test_registry_package_config", comment_char),
        format_test_string("tests.test_all_rules.TestValidRules.test_schema_and_dupes", comment_char),
    ]

    return "\n".join(lines)


@custom_rules.command("setup-config")
@click.argument("directory", type=Path)
@click.argument("kibana-version", type=str, default=load_etc_dump(["packages.yaml"])["package"]["name"])
@click.option("--overwrite", is_flag=True, help="Overwrite the existing _config.yaml file.")
@click.option(
    "--enable-prebuilt-tests", "-e", is_flag=True, help="Enable all prebuilt tests instead of default subset."
)
def setup_config(directory: Path, kibana_version: str, overwrite: bool, enable_prebuilt_tests: bool) -> None:
    """Setup the custom rules configuration directory and files with defaults."""

    config = directory / "_config.yaml"
    if not overwrite and config.exists():
        raise FileExistsError(f"{config} already exists. Use --overwrite to update")

    etc_dir = directory / "etc"
    test_config = etc_dir / "test_config.yaml"
    package_config = etc_dir / "packages.yaml"
    stack_schema_map_config = etc_dir / "stack-schema-map.yaml"
    config_files = [
        package_config,
        stack_schema_map_config,
        test_config,
        config,
    ]
    directories = [
        directory / "actions",
        directory / "action_connectors",
        directory / "exceptions",
        directory / "rules",
        directory / "rules_building_block",
        etc_dir,
    ]
    version_files = [
        etc_dir / "deprecated_rules.json",
        etc_dir / "version.lock.json",
    ]

    # Create directories
    for dir_ in directories:
        dir_.mkdir(parents=True, exist_ok=True)
        click.echo(f"Created directory: {dir_}")

    # Create version_files and populate with default content if applicable
    for file_ in version_files:
        _ = file_.write_text("{}")
        click.echo(f"Created file with default content: {file_}")

    # Create the stack-schema-map.yaml file
    stack_schema_map_content = load_etc_dump(["stack-schema-map.yaml"])
    latest_version = max(stack_schema_map_content.keys(), key=lambda v: Version.parse(v))
    latest_entry = {latest_version: stack_schema_map_content[latest_version]}
    _ = stack_schema_map_config.write_text(yaml.safe_dump(latest_entry, default_flow_style=False))

    # Create default packages.yaml
    package_content = {"package": {"name": kibana_version}}
    _ = package_config.write_text(yaml.safe_dump(package_content, default_flow_style=False))

    # Create and configure test_config.yaml
    _ = test_config.write_text(create_test_config_content(enable_prebuilt_tests))

    # Create and configure _config.yaml
    _ = config.write_text(create_config_content())

    for file_ in config_files:
        click.echo(f"Created file with default content: {file_}")

    click.echo(
        f"\n# For details on how to configure the _config.yaml file,\n"
        f"# consult: {DEFAULT_CONFIG_PATH.resolve()}\n"
        f"# or the docs: {CUSTOM_RULES_DOC_PATH.resolve()}"
    )
