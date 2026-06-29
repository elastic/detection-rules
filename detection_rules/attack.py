# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Mitre attack info."""

import json
import os
import re
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests
import yaml
from semver import Version

from .utils import cached, clear_caches, get_etc_glob_path, get_etc_path, gzip_compress, read_gzip

PLATFORMS = ["Windows", "macOS", "Linux"]
CROSSWALK_FILE = get_etc_path(["attack-crosswalk.json"])
TECHNIQUES_REDIRECT_FILE = get_etc_path(["attack-technique-redirects.json"])
ATTACK_VERSION_MAPS_DIRNAME = "attack-version-maps"

tactics_map: dict[str, Any] = {}


@cached
def load_techniques_redirect() -> dict[str, Any]:
    return json.loads(TECHNIQUES_REDIRECT_FILE.read_text())["mapping"]


def get_attack_file_path() -> Path:
    pattern = "attack-v*.json.gz"
    attack_file = get_etc_glob_path([pattern])
    if len(attack_file) < 1:
        raise FileNotFoundError(f"Missing required {pattern} file")
    if len(attack_file) != 1:
        raise FileExistsError(f"Multiple files found with {pattern} pattern. Only one is allowed")
    return Path(attack_file[0])


_, _attack_path_base = str(get_attack_file_path()).split("-v")
_ext_length = len(".json.gz")
CURRENT_ATTACK_VERSION = _attack_path_base[:-_ext_length]


def load_attack_gz() -> dict[str, Any]:
    return json.loads(read_gzip(get_attack_file_path()))


attack = load_attack_gz()

technique_lookup: dict[str, Any] = {}
revoked: dict[str, Any] = {}
deprecated: dict[str, Any] = {}

for item in attack["objects"]:
    if item["type"] == "x-mitre-tactic":
        tactics_map[item["name"]] = item["external_references"][0]["external_id"]

    if item["type"] == "attack-pattern" and item["external_references"][0]["source_name"] == "mitre-attack":
        technique_id = item["external_references"][0]["external_id"]
        technique_lookup[technique_id] = item

        if item.get("revoked"):
            revoked[technique_id] = item

        if item.get("x_mitre_deprecated"):
            deprecated[technique_id] = item

revoked = dict(sorted(revoked.items()))
deprecated = dict(sorted(deprecated.items()))
tactics = list(tactics_map)
matrix: dict[str, list[str]] = {tactic: [] for tactic in tactics}
no_tactic: list[str] = []
attack_tm = "ATT&CK\u2122"


# Enumerate over the techniques and build the matrix back up
for technique_id, technique in sorted(technique_lookup.items(), key=lambda kv: kv[1]["name"].lower()):
    kill_chain = technique.get("kill_chain_phases")
    if kill_chain:
        for tactic in kill_chain:
            tactic_name = next(
                t
                for t in tactics
                if tactic["kill_chain_name"] == "mitre-attack" and t.lower() == tactic["phase_name"].replace("-", " ")
            )
            matrix[tactic_name].append(technique_id)
        no_tactic.append(technique_id)

for val in matrix.values():
    val.sort(key=lambda tid: technique_lookup[tid]["name"].lower())


technique_lookup = OrderedDict(sorted(technique_lookup.items()))
techniques = sorted({v["name"] for _, v in technique_lookup.items()})
technique_id_list = [t for t in technique_lookup if "." not in t]
sub_technique_id_list = [t for t in technique_lookup if "." in t]


def refresh_attack_data(save: bool = True) -> tuple[dict[str, Any] | None, bytes | None]:
    """Refresh ATT&CK data from Mitre."""
    attack_path = get_attack_file_path()
    filename, _, _ = attack_path.name.rsplit(".", 2)

    def get_version_from_tag(name: str, pattern: str = "att&ck-v") -> str:
        _, version = name.lower().split(pattern, 1)
        return version

    current_version = Version.parse(get_version_from_tag(filename, "attack-v"), optional_minor_and_patch=True)

    r = requests.get("https://api.github.com/repos/mitre/cti/tags", timeout=30)
    r.raise_for_status()
    releases = [t for t in r.json() if t["name"].startswith("ATT&CK-v")]
    latest_release = max(
        releases,
        key=lambda release: Version.parse(get_version_from_tag(release["name"]), optional_minor_and_patch=True),
    )
    release_name = latest_release["name"]
    latest_version = Version.parse(get_version_from_tag(release_name), optional_minor_and_patch=True)

    if current_version >= latest_version:
        print(f"No versions newer than the current detected: {current_version}")
        return None, None

    download = f"https://raw.githubusercontent.com/mitre/cti/{release_name}/enterprise-attack/enterprise-attack.json"
    r = requests.get(download, timeout=30)
    r.raise_for_status()
    attack_data = r.json()
    compressed = gzip_compress(json.dumps(attack_data, sort_keys=True))

    if save:
        new_path = get_etc_path([f"attack-v{latest_version}.json.gz"])
        _ = new_path.write_bytes(compressed)
        attack_path.unlink()
        print(f"Replaced file: {attack_path} with {new_path}")

    return attack_data, compressed


def build_threat_map_entry(tactic: str, *technique_ids: str) -> dict[str, Any]:
    """Build rule threat map from technique IDs."""
    techniques_redirect_map = load_techniques_redirect()
    url_base = "https://attack.mitre.org/{type}/{id}/"
    tactic_id = tactics_map[tactic]
    tech_entries: dict[str, Any] = {}

    def make_entry(_id: str) -> dict[str, Any]:
        return {
            "id": _id,
            "name": technique_lookup[_id]["name"],
            "reference": url_base.format(type="techniques", id=_id.replace(".", "/")),
        }

    for tid in technique_ids:
        # fail if deprecated or else convert if it has been replaced
        if tid in deprecated:
            raise ValueError(f"Technique ID: {tid} has been deprecated and should not be used")
        if tid in techniques_redirect_map:
            tid = techniques_redirect_map[tid]  # noqa: PLW2901

        if tid not in matrix[tactic]:
            raise ValueError(f"Technique ID: {tid} does not fall under tactic: {tactic}")

        # sub-techniques
        if "." in tid:
            parent_technique, _ = tid.split(".", 1)
            tech_entries.setdefault(parent_technique, make_entry(parent_technique))
            tech_entries[parent_technique].setdefault("subtechnique", []).append(make_entry(tid))
        else:
            tech_entries.setdefault(tid, make_entry(tid))

    entry: dict[str, Any] = {
        "framework": "MITRE ATT&CK",
        "tactic": {"id": tactic_id, "name": tactic, "reference": url_base.format(type="tactics", id=tactic_id)},
    }

    if tech_entries:
        entry["technique"] = sorted(tech_entries.values(), key=lambda x: x["id"])

    return entry


def update_threat_map(rule_threat_map: list[dict[str, Any]]) -> None:
    """Update rule map techniques to reflect changes from ATT&CK."""
    for entry in rule_threat_map:
        for tech in entry["technique"]:
            tech["name"] = technique_lookup[tech["id"]]["name"]


def retrieve_redirected_id(asset_id: str) -> str | Any:
    """Get the ID for a redirected ATT&CK asset."""
    if asset_id in (tactics_map.values()):
        attack_type = "tactics"
    elif asset_id in list(technique_lookup):
        attack_type = "techniques"
    else:
        raise ValueError(f"Unknown asset_id: {asset_id}")

    response = requests.get(
        f"https://attack.mitre.org/{attack_type}/{asset_id.replace('.', '/')}",
        timeout=30,
    )
    text = response.text.strip().strip("'").lower()

    if text.startswith('<meta http-equiv="refresh"'):
        found = re.search(r'url=\/\w+\/(.+)"', text)
        if not found:
            raise ValueError("Meta refresh tag is not found")

        return found.group(1).replace("/", ".").upper()
    return None


def build_redirected_techniques_map(threads: int = 50) -> dict[str, Any]:
    """Build a mapping of revoked technique IDs to new technique IDs."""
    from multiprocessing.pool import ThreadPool

    technique_map: dict[str, Any] = {}

    def download_worker(tech_id: str) -> None:
        new = retrieve_redirected_id(tech_id)
        if new:
            technique_map[tech_id] = new

    pool = ThreadPool(processes=threads)
    _ = pool.map(download_worker, list(technique_lookup))
    pool.close()
    pool.join()

    return technique_map


def refresh_redirected_techniques_map(threads: int = 50) -> None:
    """Refresh the locally saved copy of the mapping."""
    replacement_map = build_redirected_techniques_map(threads)
    mapping = {"saved_date": time.asctime(), "mapping": replacement_map}

    _ = TECHNIQUES_REDIRECT_FILE.write_text(json.dumps(mapping, sort_keys=True, indent=2))
    # reset the cached redirect contents
    clear_caches()

    print(f"refreshed mapping file: {TECHNIQUES_REDIRECT_FILE}")


@cached
def load_crosswalk_map() -> dict[str, Any]:
    """Retrieve the replacement mapping."""
    return json.loads(CROSSWALK_FILE.read_text())["mapping"]


# Multi-version threat mapping support. Generation of a target-version mapping from a source mapping
# is driven by a curated, self-contained config (see etc/attack-version-maps/); ids absent from the
# config (or mapped to null) are dropped, so generation is accuracy-first and never invents a mapping.

# kinds of threat entry that can be remapped, with the corresponding config table attribute
_MAP_KIND_ATTRS: dict[str, str] = {
    "tactic": "tactics",
    "technique": "techniques",
    "subtechnique": "subtechniques",
}
_REQUIRED_MAP_KEYS = ("framework", "source_version", "target_version")


@dataclass
class AttackVersionMap:
    """A curated source->target ATT&CK (or other framework) mapping config."""

    framework: str
    source_version: str
    target_version: str
    path: Path
    tactics: dict[str, dict[str, str] | None] = field(default_factory=dict)  # type: ignore[reportUnknownVariableType]
    techniques: dict[str, dict[str, str] | None] = field(default_factory=dict)  # type: ignore[reportUnknownVariableType]
    subtechniques: dict[str, dict[str, str] | None] = field(default_factory=dict)  # type: ignore[reportUnknownVariableType]

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.framework, str(self.source_version), str(self.target_version))

    def _table(self, kind: str) -> dict[str, dict[str, str] | None]:
        attr = _MAP_KIND_ATTRS.get(kind)
        if attr is None:
            raise ValueError(f"Unknown threat entry kind: {kind}")
        return getattr(self, attr)

    def is_mapped(self, kind: str, source_id: str) -> bool:
        """Whether the source id has an explicit, non-null destination in the config."""
        return self._table(kind).get(source_id) is not None

    def lookup(self, kind: str, source_id: str) -> dict[str, str] | None:
        """Return the destination entry for a source id, or ``None`` if dropped/absent."""
        return self._table(kind).get(source_id)


def parse_attack_version_map(path: Path) -> AttackVersionMap:
    """Parse a single attack version mapping config file."""
    raw: dict[str, Any] = yaml.safe_load(path.read_text()) or {}
    missing = [k for k in _REQUIRED_MAP_KEYS if not raw.get(k)]
    if missing:
        raise ValueError(f"Attack version map {path} is missing required keys: {missing}")

    def _validate_table(table: dict[str, Any], kind: str) -> dict[str, dict[str, str] | None]:
        for source_id, dest in table.items():
            if dest is None:
                continue
            if not isinstance(dest, dict) or not all(k in dest for k in ("id", "name", "reference")):
                raise ValueError(
                    f"Attack version map {path}: {kind} entry '{source_id}' must map to null or an "
                    f"object with 'id', 'name', and 'reference' (got: {dest!r})"
                )
        return table

    return AttackVersionMap(
        framework=str(raw["framework"]),
        source_version=str(raw["source_version"]),
        target_version=str(raw["target_version"]),
        path=path,
        tactics=_validate_table(raw.get("tactics") or {}, "tactics"),
        techniques=_validate_table(raw.get("techniques") or {}, "techniques"),
        subtechniques=_validate_table(raw.get("subtechniques") or {}, "subtechniques"),
    )


def load_attack_version_maps(paths: list[Path]) -> dict[tuple[str, str, str], AttackVersionMap]:
    """Load mapping configs from explicit files and/or directories, indexed by (framework, src, tgt)."""
    files: list[Path] = []
    for p in paths:
        if p.is_dir():
            files.extend(sorted(set(p.glob("*.yaml")) | set(p.glob("*.yml"))))
        elif p.exists():
            files.append(p)
        else:
            raise FileNotFoundError(f"Attack version map path not found: {p}")

    maps: dict[tuple[str, str, str], AttackVersionMap] = {}
    for f in files:
        parsed = parse_attack_version_map(f)
        if parsed.key in maps:
            raise ValueError(f"Duplicate attack version map for {parsed.key}: {f} and {maps[parsed.key].path}")
        maps[parsed.key] = parsed
    return maps


def get_attack_version_map(
    framework: str,
    source_version: str,
    target_version: str,
    paths: list[Path] | None = None,
) -> AttackVersionMap:
    """Return the mapping config matching the (framework, source, target) triple."""
    if paths is None:
        from .config import parse_rules_config

        cfg_dir = parse_rules_config().attack_version_maps_dir
        if not cfg_dir:
            raise FileNotFoundError(
                "No attack version maps directory configured (set `attack_version_maps_dir` in "
                "_config.yaml) and no explicit config path was provided."
            )
        paths = [cfg_dir]

    maps = load_attack_version_maps(paths)
    key = (framework, str(source_version), str(target_version))
    if key not in maps:
        available = sorted(maps)
        raise ValueError(
            f"No attack version map found for framework={framework!r} {source_version}->{target_version}. "
            f"Available: {available}"
        )
    return maps[key]


def build_identity_version_map(framework: str, source_version: str, target_version: str) -> dict[str, Any]:
    """Build an identity (passthrough) mapping skeleton from the currently loaded ATT&CK data."""
    url_base = "https://attack.mitre.org/{type}/{id}/"
    tactics = {
        tactic_id: {"id": tactic_id, "name": name, "reference": url_base.format(type="tactics", id=tactic_id)}
        for name, tactic_id in tactics_map.items()
    }

    techniques: dict[str, dict[str, str]] = {}
    subtechniques: dict[str, dict[str, str]] = {}
    for technique_id, item in technique_lookup.items():
        if technique_id in revoked or technique_id in deprecated:
            continue
        entry = {
            "id": technique_id,
            "name": item["name"],
            "reference": url_base.format(type="techniques", id=technique_id.replace(".", "/")),
        }
        if "." in technique_id:
            subtechniques[technique_id] = entry
        else:
            techniques[technique_id] = entry

    return {
        "framework": framework,
        "source_version": source_version,
        "target_version": target_version,
        "tactics": dict(sorted(tactics.items())),
        "techniques": dict(sorted(techniques.items())),
        "subtechniques": dict(sorted(subtechniques.items())),
    }


def resolve_output_threat_version() -> tuple[str, str]:
    """Resolve which (framework, version) threat mapping should be emitted as the API `threat`."""
    from .config import (
        THREAT_MAPPING_FRAMEWORK_ENV,
        THREAT_MAPPING_VERSION_ENV,
        parse_rules_config,
    )

    cfg = parse_rules_config()
    framework = os.getenv(THREAT_MAPPING_FRAMEWORK_ENV, cfg.threat_mapping_framework)
    version = str(os.getenv(THREAT_MAPPING_VERSION_ENV, cfg.threat_mapping_version))
    return framework, version
