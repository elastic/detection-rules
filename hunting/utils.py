# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import inspect
import tomllib
from pathlib import Path
from typing import Any

import click
import urllib3
import yaml

from detection_rules.misc import get_elasticsearch_client

from .definitions import HUNTING_DIR, Hunt


def get_hunt_path(uuid: str, file_path: str) -> tuple[Path | None, str | None]:
    """Resolve the path of the hunting query using either a UUID or file path."""

    if uuid:
        # Load the index and find the hunt by UUID
        index_data = load_index_file()
        for hunts in index_data.values():
            if uuid in hunts:
                hunt_data = hunts[uuid]
                # Combine the relative path from the index with the HUNTING_DIR
                hunt_path = HUNTING_DIR / hunt_data["path"]
                return hunt_path.resolve(), None
        return None, f"No hunt found for UUID: {uuid}"

    if file_path:
        # Use the provided file path
        hunt_path = Path(file_path)
        if not hunt_path.is_file():
            return None, f"No file found at path: {file_path}"
        return hunt_path.resolve(), None

    return None, "Either UUID or file path must be provided."


def load_index_file() -> dict[str, Any]:
    """Load the hunting index.yml file."""
    index_file = HUNTING_DIR / "index.yml"
    if not index_file.exists():
        click.echo(f"No index.yml found at {index_file}.")
        return {}

    with index_file.open() as f:
        return yaml.safe_load(f)


def load_toml(source: Path | str) -> Hunt:
    """Load and validate TOML content as Hunt dataclass."""
    if isinstance(source, Path):
        if not source.is_file():
            raise FileNotFoundError(f"TOML file not found: {source}")
        contents = source.read_text(encoding="utf-8")
    else:
        contents = source

    toml_dict = tomllib.loads(contents)

    # Validate and load the content into the Hunt dataclass
    return Hunt(**toml_dict["hunt"])


def load_all_toml(base_path: Path) -> list[tuple[Hunt, Path]]:
    """Load all TOML files from the directory and return a list of Hunt configurations and their paths."""
    hunts: list[tuple[Hunt, Path]] = []
    for toml_file in base_path.rglob("*.toml"):
        hunt_config = load_toml(toml_file)
        hunts.append((hunt_config, toml_file))
    return hunts


def save_index_file(base_path: Path, directories: dict[str, Any]) -> None:
    """Save the updated index.yml file."""
    index_file = base_path / "index.yml"
    with index_file.open("w") as f:
        yaml.safe_dump(directories, f, default_flow_style=False, sort_keys=False)
    print(f"Index YAML updated at: {index_file}")


def validate_link(link: str) -> None:
    """Validate and return the link."""
    http = urllib3.PoolManager()
    response = http.request("GET", link)
    if response.status != 200:  # noqa: PLR2004
        raise ValueError(f"Invalid link: {link}")


def update_index_yml(base_path: Path) -> None:
    """Update index.yml based on the current TOML files."""
    directories = load_index_file()

    # Load all TOML files recursively
    toml_files = base_path.rglob("queries/*.toml")

    for toml_file in toml_files:
        # Load TOML and extract hunt configuration
        hunt_config = load_toml(toml_file)

        folder_name = toml_file.parent.parent.name
        uuid = hunt_config.uuid

        entry = {
            "name": hunt_config.name,
            "path": f"./{toml_file.relative_to(base_path).as_posix()}",
            "mitre": hunt_config.mitre,
        }

        # Check if the folder_name exists and if it's a list, convert it to a dictionary
        if folder_name not in directories:
            directories[folder_name] = {uuid: entry}
        else:
            if isinstance(directories[folder_name], list):
                # Convert the list to a dictionary, using UUIDs as keys
                directories[folder_name] = {item["uuid"]: item for item in directories[folder_name]}
            directories[folder_name][uuid] = entry

    # Save the updated index.yml
    save_index_file(base_path, directories)


def filter_elasticsearch_params(config: dict[str, Any]) -> dict[str, Any]:
    """Filter out unwanted keys from the config by inspecting the Elasticsearch client constructor."""
    # Get the parameter names from the Elasticsearch class constructor
    es_params = inspect.signature(get_elasticsearch_client).parameters
    return {k: v for k, v in config.items() if k in es_params}
