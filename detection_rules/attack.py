# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Mitre attack info."""

import json
import re
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

import requests
from semver import Version

from .utils import cached, clear_caches, get_etc_glob_path, get_etc_path, gzip_compress, read_gzip

PLATFORMS = ["Windows", "macOS", "Linux"]
CROSSWALK_FILE = get_etc_path(["attack-crosswalk.json"])
TECHNIQUES_REDIRECT_FILE = get_etc_path(["attack-technique-redirects.json"])

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
