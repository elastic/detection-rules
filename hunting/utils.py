# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import tomllib
from pathlib import Path

import click
import urllib3
import yaml

from detection_rules.attack import tactics_map, technique_lookup
from .definitions import HUNTING_DIR, Hunt


def load_index_file() -> dict:
    """Load the hunting index.yml file."""
    index_file = HUNTING_DIR / "index.yml"
    if not index_file.exists():
        click.echo(f"No index.yml found at {index_file}.")
        return {}

    with open(index_file, 'r') as f:
        hunting_index = yaml.safe_load(f)

    return hunting_index


def load_toml(file_path: Path) -> Hunt:
    """Load and validate TOML content as Hunt dataclass."""
    if not file_path.is_file():
        raise FileNotFoundError(f"TOML file not found: {file_path}")

    contents = file_path.read_text(encoding="utf-8")
    toml_dict = tomllib.loads(contents)

    # Validate and load the content into the Hunt dataclass
    return Hunt(**toml_dict["hunt"])


def load_all_toml(base_path: Path):
    """Load all TOML files from the directory and return a list of Hunt configurations and their paths."""
    hunts = []
    for toml_file in base_path.rglob("*.toml"):
        hunt_config = load_toml(toml_file)
        hunts.append((hunt_config, toml_file))
    return hunts


def save_index_file(base_path: Path, directories: dict) -> None:
    """Save the updated index.yml file."""
    index_file = base_path / "index.yml"
    with open(index_file, 'w') as f:
        yaml.safe_dump(directories, f, default_flow_style=False, sort_keys=False)
    print(f"Index YAML updated at: {index_file}")


def validate_link(link: str):
    """Validate and return the link."""
    http = urllib3.PoolManager()
    response = http.request('GET', link)
    if response.status != 200:
        raise ValueError(f"Invalid link: {link}")


def update_index_yml(base_path: Path) -> None:
    """Update index.yml based on the current TOML files."""
    directories = load_index_file()  # Load the existing index.yml data

    # Load all TOML files recursively
    toml_files = base_path.rglob("queries/*.toml")  # Find all TOML files in the 'queries' directory

    for toml_file in toml_files:
        # Load TOML and extract hunt configuration
        hunt_config = load_toml(toml_file)  # Parse the TOML file

        folder_name = toml_file.parent.parent.name  # Determine the folder (platform, integration, etc.)
        uuid = hunt_config.uuid  # Use the UUID as the key

        entry = {
            'name': hunt_config.name,
            'path': f"./{toml_file.relative_to(base_path).as_posix()}",  # Ensure the path links to TOML file
            'mitre': hunt_config.mitre
        }

        # Check if the folder_name exists and if it's a list, convert it to a dictionary
        if folder_name not in directories:
            directories[folder_name] = {uuid: entry}  # Initialize as a dictionary
        else:
            if isinstance(directories[folder_name], list):
                # Convert the list to a dictionary, using UUIDs as keys
                directories[folder_name] = {item['uuid']: item for item in directories[folder_name]}
            # Now we can safely use UUID as the key
            directories[folder_name][uuid] = entry

    # Save the updated index.yml
    save_index_file(base_path, directories)