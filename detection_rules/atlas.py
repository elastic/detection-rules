# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""MITRE ATLAS info, versioned like ATT&CK (`atlas-v*.json.gz`)."""

from __future__ import annotations

import json
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import requests
import yaml

from .utils import cached, clear_caches, get_etc_glob_path, get_etc_path, gzip_compress, read_gzip

if TYPE_CHECKING:
    from pathlib import Path

ATLAS_JSON_GZ_PATTERN = "atlas-v*.json.gz"
ATLAS_DIST_BASE = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist"
ATLAS_MANIFEST_URL = f"{ATLAS_DIST_BASE}/manifest.yaml"
ATLAS_URL_BASE = "https://atlas.mitre.org/{type}/{id}/"
# AML.T0000 vs AML.T0000.000 — sub-techniques contain two dots.
ATLAS_SUBTECHNIQUE_DOT_COUNT = 2
# Stack at which MITRE ATLAS threat mappings are shipped (emit transform gate).
# Keep in sync with stack_emit.MITRE_ATLAS_MIN_STACK.
MITRE_ATLAS_MIN_STACK_MAJOR_MINOR = (9, 6)


def _atlas_file_version_key(path: Path) -> tuple[int, ...]:
    """Sort key for an atlas-v*.json.gz filename (content version, e.g. 2026.08 or 5.1.0)."""
    ver = path.name.split("-v", 1)[1][: -len(".json.gz")]
    parts: list[int] = []
    for part in ver.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def get_atlas_file_path() -> Path:
    """Return the latest ATLAS data file (highest content version)."""
    atlas_files = get_etc_glob_path([ATLAS_JSON_GZ_PATTERN])
    if not atlas_files:
        raise FileNotFoundError(f"Missing required {ATLAS_JSON_GZ_PATTERN} file")
    return max(atlas_files, key=_atlas_file_version_key)


def get_atlas_file_path_for_version(version: str) -> Path:
    """Return the ATLAS data file whose content version matches `version`."""
    wanted = str(version).lstrip("v")
    atlas_files = get_etc_glob_path([ATLAS_JSON_GZ_PATTERN])
    for path in atlas_files:
        file_ver = path.name.split("-v", 1)[1][: -len(".json.gz")]
        if file_ver == wanted:
            return path
    available = [p.name.split("-v", 1)[1][: -len(".json.gz")] for p in atlas_files]
    raise FileNotFoundError(f"No ATLAS data file found for version {version!r}. Available: {available}")


def _current_atlas_version() -> str:
    try:
        path = get_atlas_file_path()
    except FileNotFoundError:
        return "unknown"
    return path.name.split("-v", 1)[1][: -len(".json.gz")]


CURRENT_ATLAS_VERSION = _current_atlas_version()


def load_atlas_gz() -> dict[str, Any]:
    """Load the latest ATLAS JSON payload."""
    return json.loads(read_gzip(get_atlas_file_path()))


@dataclass
class AtlasLookups:
    """Pre-built ATLAS lookup structures for a specific content version."""

    version: str
    tactics_map: dict[str, str]
    tactic_id_to_detail: dict[str, dict[str, str]]
    technique_lookup: OrderedDict[str, dict[str, Any]]
    matrix: dict[str, list[str]]


def _normalize_atlas_payload(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize v5 (legacy matrices list) and v6 (collection + dict maps) payloads."""
    if "collection" in raw and "tactics" in raw and isinstance(raw.get("tactics"), dict):
        version = str(raw.get("collection", {}).get("version") or raw.get("format-version") or "unknown")
        tactics_list = list(raw["tactics"].values())
        techniques_list = list(raw.get("techniques", {}).values()) if isinstance(raw.get("techniques"), dict) else []
        relationships = raw.get("relationships") or {}
        return {
            "version": version,
            "tactics": tactics_list,
            "techniques": techniques_list,
            "relationships": relationships,
        }

    # v5 / legacy: version + matrices[].tactics / techniques
    version = str(raw.get("version") or "unknown")
    matrices = raw.get("matrices") or []
    matrix_data = None
    for matrix in matrices:
        if matrix.get("id") == "ATLAS":
            matrix_data = matrix
            break
    if matrix_data is None and matrices:
        matrix_data = matrices[0]
    matrix_data = matrix_data or {}
    return {
        "version": version,
        "tactics": matrix_data.get("tactics") or [],
        "techniques": matrix_data.get("techniques") or [],
        "relationships": {},
    }


def _tactics_for_technique(
    technique: dict[str, Any],
    relationships: dict[str, Any],
    tactic_id_to_name: dict[str, str],
) -> list[str]:
    """Return tactic IDs for a technique from v6 relationships or a v5 tactics field."""
    tech_id = technique.get("id", "")
    rel = relationships.get(tech_id) or {}
    achieved = [entry.get("target") for entry in rel.get("achieves") or [] if entry.get("target")]
    if achieved:
        return [tid for tid in achieved if tid in tactic_id_to_name]
    raw_tactics = technique.get("tactics") or []
    return [tid for tid in raw_tactics if tid in tactic_id_to_name]


def _build_lookups(version: str, raw: dict[str, Any]) -> AtlasLookups:
    """Build ATLAS lookup structures from a normalized or raw ATLAS payload."""
    normalized = _normalize_atlas_payload(raw)
    version = version or str(normalized.get("version") or "unknown")

    tactics_map: dict[str, str] = {}
    tactic_id_to_detail: dict[str, dict[str, str]] = {}
    for tactic in normalized["tactics"]:
        tactic_id = str(tactic["id"])
        tactic_name = str(tactic["name"])
        tactics_map[tactic_name] = tactic_id
        tactic_id_to_detail[tactic_id] = {
            "id": tactic_id,
            "name": tactic_name,
            "reference": ATLAS_URL_BASE.format(type="tactics", id=tactic_id),
        }

    technique_lookup: dict[str, dict[str, Any]] = {}
    matrix: dict[str, list[str]] = {name: [] for name in tactics_map}
    relationships = normalized.get("relationships") or {}

    for technique in normalized["techniques"]:
        technique_id = str(technique["id"])
        tactic_ids = _tactics_for_technique(technique, relationships, tactic_id_to_detail)
        technique_lookup[technique_id] = {
            "name": technique["name"],
            "id": technique_id,
            "tactics": tactic_ids,
        }
        for tactic_id in tactic_ids:
            tactic_name = tactic_id_to_detail[tactic_id]["name"]
            if technique_id not in matrix[tactic_name]:
                matrix[tactic_name].append(technique_id)

    for val in matrix.values():
        val.sort(key=lambda tid: technique_lookup.get(tid, {}).get("name", "").lower())

    return AtlasLookups(
        version=version,
        tactics_map=tactics_map,
        tactic_id_to_detail=tactic_id_to_detail,
        technique_lookup=OrderedDict(sorted(technique_lookup.items())),
        matrix=matrix,
    )


@cached
def build_atlas_lookups_for_version(version: str) -> AtlasLookups:
    """Load and cache ATLAS lookup structures for a specific content version."""
    path = get_atlas_file_path_for_version(version)
    raw = json.loads(read_gzip(path))
    return _build_lookups(version, raw)


def _empty_lookups() -> AtlasLookups:
    return AtlasLookups(
        version="unknown",
        tactics_map={},
        tactic_id_to_detail={},
        technique_lookup=OrderedDict(),
        matrix={},
    )


def _load_latest_lookups() -> AtlasLookups:
    if CURRENT_ATLAS_VERSION == "unknown":
        return _empty_lookups()
    try:
        return build_atlas_lookups_for_version(CURRENT_ATLAS_VERSION)
    except FileNotFoundError:
        return _empty_lookups()


_latest = _load_latest_lookups()
tactics_map = _latest.tactics_map
technique_lookup = _latest.technique_lookup
matrix = _latest.matrix
tactics = list(tactics_map)
techniques = sorted({v["name"] for _, v in technique_lookup.items()})
technique_id_list = [t for t in technique_lookup if t.count(".") < ATLAS_SUBTECHNIQUE_DOT_COUNT]
sub_technique_id_list = [t for t in technique_lookup if t.count(".") >= ATLAS_SUBTECHNIQUE_DOT_COUNT]


def _latest_manifest_release() -> tuple[str, str]:
    """Return (content_version, dist-relative yaml path) for the newest v6 ATLAS release."""
    response = requests.get(ATLAS_MANIFEST_URL, timeout=30)
    response.raise_for_status()
    manifest = yaml.safe_load(response.text)
    if not isinstance(manifest, list) or not manifest:
        raise ValueError("ATLAS manifest is empty or invalid")

    def _release_key(entry: dict[str, Any]) -> tuple[int, ...]:
        rel = str(entry.get("release") or "0")
        parts: list[int] = []
        for part in rel.split("."):
            try:
                parts.append(int(part))
            except ValueError:
                parts.append(0)
        return tuple(parts)

    latest = max(manifest, key=_release_key)
    content_version = str(latest["release"])
    versions = latest.get("versions") or []
    v6 = next((v for v in versions if str(v.get("format-version", "")).startswith("6.")), None)
    if v6 is None and versions:
        v6 = versions[0]
    if v6 is None or not v6.get("path"):
        raise ValueError(f"No ATLAS distribution path for release {content_version}")
    return content_version, str(v6["path"])


def download_atlas_data(save: bool = True) -> dict[str, Any] | None:
    """Download the latest ATLAS YAML and optionally persist it as versioned json.gz."""
    content_version, rel_path = _latest_manifest_release()
    url = f"{ATLAS_DIST_BASE}/{rel_path.lstrip('/')}"
    response = requests.get(url, timeout=60)
    response.raise_for_status()
    atlas_data = yaml.safe_load(response.text)
    if not isinstance(atlas_data, dict):
        raise TypeError("ATLAS download did not return a mapping")

    if save:
        compressed = gzip_compress(json.dumps(atlas_data, sort_keys=True, default=str))
        new_path = get_etc_path([f"atlas-v{content_version}.json.gz"])
        _ = new_path.write_bytes(compressed)
        print(f"Downloaded ATLAS {content_version} to {new_path}")

    return atlas_data


def refresh_atlas_data(save: bool = True) -> tuple[dict[str, Any] | None, bytes | None]:
    """Refresh ATLAS data from MITRE when a newer content version exists."""
    try:
        current_key = _atlas_file_version_key(get_atlas_file_path())
        current_version = CURRENT_ATLAS_VERSION
    except FileNotFoundError:
        current_key = (0,)
        current_version = "none"

    content_version, rel_path = _latest_manifest_release()
    latest_key = tuple(int(p) if p.isdigit() else 0 for p in str(content_version).split("."))
    if current_key >= latest_key:
        print(f"No versions newer than the current detected: {current_version}")
        return None, None

    url = f"{ATLAS_DIST_BASE}/{rel_path.lstrip('/')}"
    response = requests.get(url, timeout=60)
    response.raise_for_status()
    atlas_data = yaml.safe_load(response.text)
    compressed = gzip_compress(json.dumps(atlas_data, sort_keys=True, default=str))

    if save:
        new_path = get_etc_path([f"atlas-v{content_version}.json.gz"])
        _ = new_path.write_bytes(compressed)
        print(f"Saved ATLAS {content_version} to {new_path} (previous: {current_version})")
        clear_caches()

    return atlas_data, compressed


def load_atlas_yaml() -> dict[str, Any]:
    """Load ATLAS data (kept for callers that still expect YAML-shaped dicts)."""
    return load_atlas_gz()


def canonical_technique_id(technique_id: str) -> str:
    """Normalize a tagged/authored ATLAS technique id to the AML.Txxxx form."""
    tid = technique_id.strip()
    if tid.upper().startswith("AML."):
        return f"AML.{tid[4:]}" if tid.startswith("aml.") else tid
    if tid.upper().startswith("T") and tid[1:2].isdigit():
        return f"AML.{tid}"
    return tid


def build_threat_map_entry(tactic_name: str, *technique_ids: str) -> dict[str, Any]:
    """Build rule threat map from ATLAS technique IDs."""
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
            "reference": ATLAS_URL_BASE.format(type="techniques", id=_id),
        }

    for raw_tid in technique_ids:
        tid = canonical_technique_id(raw_tid)
        if tid not in technique_lookup:
            raise ValueError(f"Unknown ATLAS technique ID: {tid}")

        tech_info = technique_lookup[tid]
        tech_tactic_ids = tech_info.get("tactics", [])
        if tactic_id not in tech_tactic_ids:
            raise ValueError(f"ATLAS technique ID: {tid} does not fall under tactic: {tactic_name}")

        # Sub-techniques are AML.T0000.000 (two dots)
        if tid.count(".") >= ATLAS_SUBTECHNIQUE_DOT_COUNT:
            parent_technique = tid.rsplit(".", 1)[0]
            tech_entries.setdefault(parent_technique, make_entry(parent_technique))
            tech_entries[parent_technique].setdefault("subtechnique", []).append(make_entry(tid))
        else:
            tech_entries.setdefault(tid, make_entry(tid))

    entry: dict[str, Any] = {
        "framework": "MITRE ATLAS",
        "tactic": {
            "id": tactic_id,
            "name": tactic_name,
            "reference": ATLAS_URL_BASE.format(type="tactics", id=tactic_id),
        },
    }

    if tech_entries:
        entry["technique"] = sorted(tech_entries.values(), key=lambda x: x["id"])

    return entry
