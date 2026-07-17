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
from typing import Any, cast

import requests
import yaml
from semver import Version

from .config import (
    DEFAULT_THREAT_MAPPING_FRAMEWORK,
    DEFAULT_THREAT_MAPPING_VERSION,
    THREAT_MAPPING_FRAMEWORK_ENV,
    THREAT_MAPPING_VERSION_ENV,
    load_current_package_version,
    parse_rules_config,
)
from .utils import cached, clear_caches, get_etc_glob_path, get_etc_path, gzip_compress, read_gzip

PLATFORMS = ["Windows", "macOS", "Linux"]
CROSSWALK_FILE = get_etc_path(["attack-crosswalk.json"])
TECHNIQUES_REDIRECT_FILE = get_etc_path(["attack-technique-redirects.json"])
ATTACK_VERSION_MAPS_DIRNAME = "attack-version-maps"
# Stack at which ATT&CK v19 becomes the default shipped threat mapping (emit transform gate).
MITRE_V19_MIN_STACK = Version(9, 5, 0)

tactics_map: dict[str, Any] = {}


@cached
def load_techniques_redirect() -> dict[str, Any]:
    return json.loads(TECHNIQUES_REDIRECT_FILE.read_text())["mapping"]


def _attack_file_version(path: Path) -> Version:
    """Extract the semver from an ATT&CK gz filename for sorting."""
    ver = path.name.split("-v", 1)[1][: -len(".json.gz")]
    return Version.parse(ver, optional_minor_and_patch=True)


def get_attack_file_path() -> Path:
    """Return the baseline ATT&CK data file (lowest available version)."""
    pattern = "attack-v*.json.gz"
    attack_files = get_etc_glob_path([pattern])
    if not attack_files:
        raise FileNotFoundError(f"Missing required {pattern} file")
    return min(attack_files, key=_attack_file_version)


def get_attack_file_path_for_version(version: str) -> Path:
    """Return the ATT&CK data file whose major version matches version."""
    major = version.split(".", maxsplit=1)[0]
    attack_files = get_etc_glob_path(["attack-v*.json.gz"])
    for path in sorted(attack_files, key=_attack_file_version, reverse=True):
        if path.name.split("-v", 1)[1][: -len(".json.gz")].split(".")[0] == major:
            return path
    available = [p.name.split("-v", 1)[1][: -len(".json.gz")] for p in attack_files]
    raise FileNotFoundError(f"No ATT&CK data file found for version {version!r}. Available: {available}")


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


@dataclass
class AttackLookups:
    """Pre-built ATT&CK lookup structures for a specific version."""

    version: str
    tactics_map: dict[str, str]
    tactic_id_to_detail: dict[str, dict[str, str]]
    technique_lookup: OrderedDict[str, Any]
    revoked: dict[str, Any]
    deprecated: dict[str, Any]
    matrix: dict[str, list[str]]


def _build_lookups(version: str, raw: dict[str, Any]) -> AttackLookups:
    """Build ATT&CK lookup structures from raw STIX data."""
    _tactics_map: dict[str, str] = {}
    _tactic_id_to_detail: dict[str, dict[str, str]] = {}
    _technique_lookup: dict[str, Any] = {}
    _revoked: dict[str, Any] = {}
    _deprecated: dict[str, Any] = {}

    for item in raw["objects"]:
        if item["type"] == "x-mitre-tactic":
            tactic_name = item["name"]
            tactic_id = item["external_references"][0]["external_id"]
            tactic_url = item["external_references"][0].get("url", f"https://attack.mitre.org/tactics/{tactic_id}/")
            _tactics_map[tactic_name] = tactic_id
            _tactic_id_to_detail[tactic_id] = {"id": tactic_id, "name": tactic_name, "reference": tactic_url}
        if item["type"] == "attack-pattern" and item["external_references"][0]["source_name"] == "mitre-attack":
            tid = item["external_references"][0]["external_id"]
            _technique_lookup[tid] = item
            if item.get("revoked"):
                _revoked[tid] = item
            if item.get("x_mitre_deprecated"):
                _deprecated[tid] = item

    _tactics_list = list(_tactics_map)
    _matrix: dict[str, list[str]] = {t: [] for t in _tactics_list}
    for tid, technique in sorted(_technique_lookup.items(), key=lambda kv: kv[1]["name"].lower()):
        kill_chain = technique.get("kill_chain_phases")
        if kill_chain:
            for phase in kill_chain:
                if phase["kill_chain_name"] != "mitre-attack":
                    continue
                tactic_name = next(
                    (t for t in _tactics_list if t.lower() == phase["phase_name"].replace("-", " ")),
                    None,
                )
                if tactic_name:
                    _matrix[tactic_name].append(tid)
    for val in _matrix.values():
        val.sort(key=lambda t: _technique_lookup[t]["name"].lower())

    return AttackLookups(
        version=version,
        tactics_map=_tactics_map,
        tactic_id_to_detail=_tactic_id_to_detail,
        technique_lookup=OrderedDict(sorted(_technique_lookup.items())),
        revoked=dict(sorted(_revoked.items())),
        deprecated=dict(sorted(_deprecated.items())),
        matrix=_matrix,
    )


@cached
def build_attack_lookups_for_version(version: str) -> AttackLookups:
    """Load and cache ATT&CK lookup structures for a specific version."""
    path = get_attack_file_path_for_version(version)
    raw = json.loads(read_gzip(path))
    return _build_lookups(version, raw)


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
    auto_derive_missing: bool = False

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
        """Return the destination entry for a source id, or None if dropped/absent."""
        return self._table(kind).get(source_id)

    def resolve(
        self, kind: str, source_id: str, target_lookups: "AttackLookups | None" = None
    ) -> dict[str, str] | None:
        """Return the destination entry; explicit config takes precedence, then auto-derives from STIX if enabled."""
        table = self._table(kind)
        if source_id in table:
            return table[source_id]
        if self.auto_derive_missing and target_lookups is not None:
            return self._derive_from_stix(kind, source_id, target_lookups)
        return None

    def _derive_from_stix(self, kind: str, source_id: str, target_lookups: "AttackLookups") -> dict[str, str] | None:
        """Derive a destination entry from STIX target data for a source id not in the config."""
        url_base = "https://attack.mitre.org/{type}/{id}/"
        if kind == "tactic":
            detail = target_lookups.tactic_id_to_detail.get(source_id)
            if detail is None:
                return None
            return dict(detail)
        if kind in ("technique", "subtechnique"):
            item = target_lookups.technique_lookup.get(source_id)
            if item is None or item.get("revoked") or item.get("x_mitre_deprecated"):
                return None
            url_id = source_id.replace(".", "/")
            raw_url = item["external_references"][0].get("url", url_base.format(type="techniques", id=url_id))
            url = raw_url if raw_url.endswith("/") else raw_url + "/"
            return {"id": source_id, "name": item["name"], "reference": url}
        return None


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
        auto_derive_missing=bool(raw.get("auto_derive_missing", False)),
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
    """Build a cross-version identity skeleton using source IDs and target-version names."""
    # Source data: determines which IDs appear as source keys.
    try:
        src = build_attack_lookups_for_version(source_version)
        _src_tactics_map = src.tactics_map
        _src_technique_lookup = src.technique_lookup
        _src_revoked = src.revoked
        _src_deprecated = src.deprecated
    except FileNotFoundError:
        _src_tactics_map = tactics_map
        _src_technique_lookup = technique_lookup
        _src_revoked = revoked
        _src_deprecated = deprecated

    # Target data: resolves destination names/references where the same ID exists.
    try:
        tgt = build_attack_lookups_for_version(target_version)
        _tgt_tactic_id_to_name: dict[str, str] = {v: k for k, v in tgt.tactics_map.items()}
        _tgt_technique_lookup: dict[str, Any] = dict(tgt.technique_lookup)
    except FileNotFoundError:
        _tgt_tactic_id_to_name = {}
        _tgt_technique_lookup = {}

    url_base = "https://attack.mitre.org/{type}/{id}/"

    # Tactics: source IDs as keys, target name if the ID still exists in the target version.
    out_tactics: dict[str, dict[str, str]] = {
        tactic_id: {
            "id": tactic_id,
            "name": _tgt_tactic_id_to_name.get(tactic_id, name),
            "reference": url_base.format(type="tactics", id=tactic_id),
        }
        for name, tactic_id in _src_tactics_map.items()
    }

    # Techniques and subtechniques: source IDs as keys, target name if available.
    out_techniques: dict[str, dict[str, str]] = {}
    out_subtechniques: dict[str, dict[str, str]] = {}
    for technique_id, item in _src_technique_lookup.items():
        if technique_id in _src_revoked or technique_id in _src_deprecated:
            continue
        tgt_item = _tgt_technique_lookup.get(technique_id, item)
        entry: dict[str, str] = {
            "id": technique_id,
            "name": tgt_item["name"],
            "reference": url_base.format(type="techniques", id=technique_id.replace(".", "/")),
        }
        if "." in technique_id:
            out_subtechniques[technique_id] = entry
        else:
            out_techniques[technique_id] = entry

    return {
        "framework": framework,
        "source_version": source_version,
        "target_version": target_version,
        "tactics": dict(sorted(out_tactics.items())),
        "techniques": dict(sorted(out_techniques.items())),
        "subtechniques": dict(sorted(out_subtechniques.items())),
    }


# Sentinel: auto-load STIX lookups for the target version (default convert path).
_LOOKUPS_AUTO = object()


@cached
def _get_default_version_map(framework: str, source_version: str, target_version: str) -> AttackVersionMap | None:
    """Return the default configured version map for a triple, cached; None if unavailable."""
    try:
        return get_attack_version_map(framework, source_version, target_version)
    except (FileNotFoundError, ValueError):
        return None


def convert_threat_to_version(  # noqa: PLR0912, PLR0913, PLR0915
    threat: list[dict[str, Any]],
    source_version: str,
    target_version: str,
    framework: str,
    *,
    vmap: AttackVersionMap | None = None,
    target_lookups: AttackLookups | None | object = _LOOKUPS_AUTO,
    dropped: list[str] | None = None,
    moved: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Convert a raw threat list to the target version; techniques follow tactic migrations.

    Shared by build-time emit (stack_emit mitre_attack_v19) and the CLI remapper
    (devtools._remap_threat_entries). When a source tactic is dropped (e.g. Defense Evasion
    in v19), techniques are still placed using the target STIX matrix when lookups are available.

    Pass an explicit vmap / target_lookups to reuse a caller-loaded config (CLI). Use
    target_lookups=None to skip STIX membership checks. Returns [] when no map/STIX
    data is available on the default (auto) path.
    """
    if vmap is None:
        vmap = _get_default_version_map(framework, source_version, target_version)
        if vmap is None:
            return []

    lookups: AttackLookups | None
    if target_lookups is _LOOKUPS_AUTO:
        try:
            lookups = build_attack_lookups_for_version(target_version)
        except FileNotFoundError:
            return []
    else:
        lookups = target_lookups  # type: ignore[assignment]

    tgt_tactic_id_to_name: dict[str, str] = {}
    tgt_tech_to_tactic_names: dict[str, list[str]] = {}
    if lookups is not None:
        tgt_tactic_id_to_name = {v: k for k, v in lookups.tactics_map.items()}
        for tname, tids in lookups.matrix.items():
            for tid in tids:
                tgt_tech_to_tactic_names.setdefault(tid, []).append(tname)

    entries_by_tactic: dict[str, dict[str, Any]] = {}
    passthru: list[dict[str, Any]] = []
    tactic_only_ids: set[str] = set()

    def _get_or_create(tactic_detail: dict[str, str]) -> dict[str, Any]:
        tid = tactic_detail["id"]
        if tid not in entries_by_tactic:
            entries_by_tactic[tid] = {
                "framework": framework,
                "tactic": {
                    "id": tactic_detail["id"],
                    "name": tactic_detail["name"],
                    "reference": tactic_detail["reference"],
                },
                "technique": [],
            }
        return entries_by_tactic[tid]

    def _merge_technique(tactic_entry: dict[str, Any], new_technique: dict[str, Any]) -> None:
        for existing in tactic_entry["technique"]:
            if existing["id"] == new_technique["id"]:
                existing_sub_ids = {s["id"] for s in existing.get("subtechnique", [])}
                merged = existing.get("subtechnique", []) + [
                    s for s in new_technique.get("subtechnique", []) if s["id"] not in existing_sub_ids
                ]
                if merged:
                    existing["subtechnique"] = sorted(merged, key=lambda s: s["id"])
                return
        tactic_entry["technique"].append(new_technique)

    def _tactics_for_technique(
        tech_id: str,
        tech_name: str,
        mapped_tactic: dict[str, str] | None,
    ) -> list[dict[str, str]]:
        if not tgt_tactic_id_to_name:
            return [mapped_tactic] if mapped_tactic is not None else []

        tech_tactic_names = tgt_tech_to_tactic_names.get(tech_id, [])
        if mapped_tactic is not None:
            tgt_tactic_name = tgt_tactic_id_to_name.get(mapped_tactic["id"])
            if not tech_tactic_names or (tgt_tactic_name and tgt_tactic_name in tech_tactic_names):
                return [mapped_tactic]

        if lookups is None:
            return [mapped_tactic] if mapped_tactic is not None else []

        details = [
            detail
            for tname in tech_tactic_names
            for tid in [lookups.tactics_map.get(tname, "")]
            for detail in [lookups.tactic_id_to_detail.get(tid)]
            if detail
        ]
        if details and mapped_tactic is not None and moved is not None:
            new_str = ", ".join(f"{d['id']} ({d['name']})" for d in details)
            moved.append(
                f"technique {tech_id} ({tech_name}) — migrated from "
                f"{mapped_tactic['id']} ({mapped_tactic['name']}) to {new_str} "
                f"in v{lookups.version}"
            )
        if details:
            return details
        return [mapped_tactic] if mapped_tactic is not None else []

    for entry in threat:
        if entry.get("framework") != framework:
            passthru.append(entry)
            continue

        tactic = cast("dict[str, Any]", entry.get("tactic") or {})
        tactic_id = str(tactic.get("id", ""))
        tactic_name = str(tactic.get("name", tactic_id))
        tactic_dest = vmap.resolve("tactic", tactic_id, lookups)
        source_techniques = cast("list[dict[str, Any]]", entry.get("technique") or [])

        if not source_techniques:
            if tactic_dest is not None:
                tactic_only_ids.add(tactic_dest["id"])
                _ = _get_or_create(tactic_dest)
            elif dropped is not None:
                dropped.append(f"tactic {tactic_id} ({tactic_name})")
            continue

        for technique in source_techniques:
            tech_id = str(technique.get("id", ""))
            tech_name = str(technique.get("name", tech_id))
            tech_dest = vmap.resolve("technique", tech_id, lookups)
            if tech_dest is None:
                if dropped is not None:
                    dropped.append(f"technique {tech_id} ({tech_name})")
                continue

            new_subs: list[dict[str, Any]] = []
            for sub in cast("list[dict[str, Any]]", technique.get("subtechnique") or []):
                sub_id = str(sub.get("id", ""))
                sub_name = str(sub.get("name", sub_id))
                sub_dest = vmap.resolve("subtechnique", sub_id, lookups)
                if sub_dest is None:
                    if dropped is not None:
                        dropped.append(f"subtechnique {sub_id} ({sub_name})")
                    continue
                new_subs.append({"id": sub_dest["id"], "name": sub_dest["name"], "reference": sub_dest["reference"]})

            for tactic_for_tech in _tactics_for_technique(tech_dest["id"], tech_dest["name"], tactic_dest):
                new_tech: dict[str, Any] = {
                    "id": tech_dest["id"],
                    "name": tech_dest["name"],
                    "reference": tech_dest["reference"],
                }
                if new_subs:
                    new_tech["subtechnique"] = [dict(s) for s in new_subs]
                _merge_technique(_get_or_create(tactic_for_tech), new_tech)

    return passthru + [
        {k: v for k, v in e.items() if k != "technique" or v}
        for e in entries_by_tactic.values()
        if e.get("technique") or e["tactic"]["id"] in tactic_only_ids
    ]


def resolve_output_threat_version(stack: Version | str | None = None) -> tuple[str, str]:
    """Resolve which (framework, version) threat mapping should be emitted as the API `threat`.

    stack defaults to the current package version. Emit transforms should pass the same
    stack used for transforms_for_stack so auto-promotion stays aligned with the registry.
    """
    cfg = parse_rules_config()
    framework = os.getenv(THREAT_MAPPING_FRAMEWORK_ENV, cfg.threat_mapping_framework)
    version = str(os.getenv(THREAT_MAPPING_VERSION_ENV, cfg.threat_mapping_version))

    # Auto-promote to v19 when targeting a stack that ships with v19 ATT&CK mappings,
    # but only when neither the env var nor the config file has explicitly pinned a version.
    # An explicit pin (even "18") suppresses auto-promotion so callers can lock a version.
    env_version_explicit = os.getenv(THREAT_MAPPING_VERSION_ENV) is not None
    if (
        not env_version_explicit
        and not cfg.threat_mapping_version_pinned
        and framework == DEFAULT_THREAT_MAPPING_FRAMEWORK
        and version == DEFAULT_THREAT_MAPPING_VERSION
    ):
        try:
            raw = stack if stack is not None else load_current_package_version()
            stack_ver = raw if isinstance(raw, Version) else Version.parse(str(raw), optional_minor_and_patch=True)
            if stack_ver >= MITRE_V19_MIN_STACK:
                version = "19"
        except ValueError:
            pass

    return framework, version
