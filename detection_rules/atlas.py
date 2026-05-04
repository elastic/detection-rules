# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Mitre ATLAS info."""

from collections import OrderedDict
from pathlib import Path
from typing import Any

import requests
import yaml
from semver import Version

from .utils import cached, clear_caches, get_etc_path

ATLAS_FILE = get_etc_path(["ATLAS.yaml"])

# Maps tactic name to tactic ID (e.g., "Collection" -> "AML.TA0009")
tactics_map: dict[str, str] = {}
technique_lookup: dict[str, dict[str, Any]] = {}
matrix: dict[str, list[str]] = {}  # Maps tactic name to list of technique IDs


@cached
def get_atlas_file_path() -> Path:
    """Get the path to the ATLAS YAML file."""
    if not ATLAS_FILE.exists():
        # Try to download it if it doesn't exist
        _ = download_atlas_data()
    return ATLAS_FILE


def download_atlas_data(save: bool = True) -> dict[str, Any] | None:
    """Download ATLAS data from MITRE."""
    url = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    atlas_data = yaml.safe_load(r.text)

    if save:
        _ = ATLAS_FILE.write_text(r.text)
        print(f"Downloaded ATLAS data to {ATLAS_FILE}")

    return atlas_data


@cached
def load_atlas_yaml() -> dict[str, Any]:
    """Load ATLAS data from YAML file."""
    atlas_file = get_atlas_file_path()
    return yaml.safe_load(atlas_file.read_text())


atlas = load_atlas_yaml()

# Extract version
CURRENT_ATLAS_VERSION = atlas.get("version", "unknown")

# Process the ATLAS matrix
# Look for the specific ATLAS matrix by ID, fall back to first matrix if not found
ATLAS_MATRIX_ID = "ATLAS"
matrix_data = None

if "matrices" in atlas and len(atlas["matrices"]) > 0:
    # Try to find the ATLAS matrix by ID
    for m in atlas["matrices"]:
        if m.get("id") == ATLAS_MATRIX_ID:
            matrix_data = m
            break

    # Fall back to first matrix if ATLAS matrix not found by ID
    if matrix_data is None:
        matrix_data = atlas["matrices"][0]

if matrix_data is not None:
    # Build tactics map
    if "tactics" in matrix_data:
        for tactic in matrix_data["tactics"]:
            tactic_id = tactic["id"]
            tactic_name = tactic["name"]
            tactics_map[tactic_name] = tactic_id

    # Build technique lookup and matrix
    if "techniques" in matrix_data:
        for technique in matrix_data["techniques"]:
            technique_id = technique["id"]
            technique_name = technique["name"]
            technique_tactics = technique.get("tactics", [])

            # Store technique info
            technique_lookup[technique_id] = {
                "name": technique_name,
                "id": technique_id,
                "tactics": technique_tactics,
            }

            # Build matrix: map tactic IDs to technique IDs
            for tech_tactic_id in technique_tactics:
                # Find tactic name from ID
                tech_tactic_name = next((name for name, tid in tactics_map.items() if tid == tech_tactic_id), None)
                if tech_tactic_name:
                    if tech_tactic_name not in matrix:
                        matrix[tech_tactic_name] = []
                    if technique_id not in matrix[tech_tactic_name]:
                        matrix[tech_tactic_name].append(technique_id)

# Sort matrix values
for val in matrix.values():
    val.sort(key=lambda tid: technique_lookup.get(tid, {}).get("name", "").lower())

technique_lookup = OrderedDict(sorted(technique_lookup.items()))
techniques = sorted({v["name"] for _, v in technique_lookup.items()})
technique_id_list = [t for t in technique_lookup if "." not in t]
sub_technique_id_list = [t for t in technique_lookup if "." in t]
tactics = list(tactics_map)


def refresh_atlas_data(save: bool = True) -> dict[str, Any] | None:
    """Refresh ATLAS data from MITRE."""
    atlas_file = get_atlas_file_path()
    current_version_str = CURRENT_ATLAS_VERSION

    try:
        current_version = Version.parse(current_version_str, optional_minor_and_patch=True)
    except (ValueError, TypeError):
        # If version parsing fails, download anyway
        current_version = Version.parse("0.0.0", optional_minor_and_patch=True)

    # Get latest version from GitHub
    r = requests.get("https://api.github.com/repos/mitre-atlas/atlas-data/tags", timeout=30)
    r.raise_for_status()
    releases = r.json()
    if not releases:
        print("No releases found")
        return None

    # Find latest version (tags might be like "v5.1.0" or "5.1.0")
    latest_release = None
    latest_version = current_version
    for release in releases:
        tag_name = release["name"].lstrip("v")
        try:
            ver = Version.parse(tag_name, optional_minor_and_patch=True)
            if ver > latest_version:
                latest_version = ver
                latest_release = release
        except (ValueError, TypeError):
            continue

    if latest_release is None:
        print(f"No versions newer than the current detected: {current_version_str}")
        return None

    download = f"https://raw.githubusercontent.com/mitre-atlas/atlas-data/{latest_release['name']}/dist/ATLAS.yaml"
    r = requests.get(download, timeout=30)
    r.raise_for_status()
    atlas_data = yaml.safe_load(r.text)

    if save:
        _ = atlas_file.write_text(r.text)
        print(f"Replaced file: {atlas_file} with version {latest_version}")

    # Clear cache to reload
    clear_caches()

    return atlas_data


def build_threat_map_entry(tactic_name: str, *technique_ids: str) -> dict[str, Any]:
    """Build rule threat map from ATLAS technique IDs."""
    url_base = "https://atlas.mitre.org/{type}/{id}/"
    tactic_id = tactics_map.get(tactic_name)
    if not tactic_id:
        raise ValueError(f"Unknown ATLAS tactic: {tactic_name}")

    tech_entries: dict[str, Any] = {}

    def make_entry(_id: str) -> dict[str, Any]:
        tech_info = technique_lookup.get(_id)
        if not tech_info:
            raise ValueError(f"Unknown ATLAS technique ID: {_id}")
        return {
            "id": _id,
            "name": tech_info["name"],
            "reference": url_base.format(type="techniques", id=_id.replace(".", "/")),
        }

    for tid in technique_ids:
        if tid not in technique_lookup:
            raise ValueError(f"Unknown ATLAS technique ID: {tid}")

        tech_info = technique_lookup[tid]
        tech_tactic_ids = tech_info.get("tactics", [])
        if tactic_id not in tech_tactic_ids:
            raise ValueError(f"ATLAS technique ID: {tid} does not fall under tactic: {tactic_name}")

        # Handle sub-techniques (e.g., AML.T0000.000)
        if "." in tid and tid.count(".") > 1:
            # This is a sub-technique
            parts = tid.rsplit(".", 1)
            parent_technique = parts[0]
            tech_entries.setdefault(parent_technique, make_entry(parent_technique))
            tech_entries[parent_technique].setdefault("subtechnique", []).append(make_entry(tid))
        else:
            tech_entries.setdefault(tid, make_entry(tid))

    entry: dict[str, Any] = {
        "framework": "MITRE ATLAS",
        "tactic": {
            "id": tactic_id,
            "name": tactic_name,
            "reference": url_base.format(type="tactics", id=tactic_id),
        },
    }

    if tech_entries:
        entry["technique"] = sorted(tech_entries.values(), key=lambda x: x["id"])

    return entry
