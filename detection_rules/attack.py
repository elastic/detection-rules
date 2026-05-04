# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Mitre attack info."""

import json
import re
import time
from collections import OrderedDict, defaultdict
from pathlib import Path
from typing import Any

import requests
from semver import Version

from .schemas import definitions
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

# External tactic id (TAxxxx) -> current MITRE ATT&CK data display name (e.g. TA0005 -> Stealth after v19 rename).
tactic_id_to_name: dict[str, str] = {ext_id: name for name, ext_id in tactics_map.items()}

technique_lookup = OrderedDict(sorted(technique_lookup.items()))
techniques = sorted({v["name"] for _, v in technique_lookup.items()})
technique_id_list = [t for t in technique_lookup if "." not in t]
sub_technique_id_list = [t for t in technique_lookup if "." in t]


def secondary_matrix_preferences_for_tactic_id(tactic_external_id: str) -> tuple[str, ...]:
    """Ordered extra tactic *names* when the row's primary tactic column does not contain a technique.

    Source: ``definitions.ATTACK_TACTIC_MIGRATION_SECONDARY_MATRIX_PREFERENCES``.
    """
    return definitions.ATTACK_TACTIC_MIGRATION_SECONDARY_MATRIX_PREFERENCES.get(tactic_external_id, ())


def filename_legacy_stem_prefixes() -> tuple[str, ...]:
    """Basename prefixes (e.g. ``defense_evasion_``) to rewrite using ``threat[0]`` tactic slug after a rename.

    Source: ``definitions.ATTACK_TACTIC_MIGRATION_FILENAME_LEGACY_STEM_PREFIXES``.
    """
    return definitions.ATTACK_TACTIC_MIGRATION_FILENAME_LEGACY_STEM_PREFIXES


@cached
def priority_mitre_tactic_display_names_from_migration_hints() -> tuple[str, ...]:
    """Tactic names that sort before others when saving ``rule.threat`` during migrate / update-rules.

    **Where:** ``devtools._mitre_threat_persist_sort_key`` only.

    **Why:** Rules list multiple tactics; CI expects filenames to match ``threat[0]``. Without this,
    pure alphabetical order can put unrelated tactics first after MITRE renames legacy rows.

    **How:** For each key in ``definitions.ATTACK_TACTIC_MIGRATION_SECONDARY_MATRIX_PREFERENCES``, take that
    TA's current display name from ``tactic_id_to_name``, then each tuple entry, deduplicated.
    """
    order: list[str] = []
    for tactic_id, secondaries in definitions.ATTACK_TACTIC_MIGRATION_SECONDARY_MATRIX_PREFERENCES.items():
        primary = tactic_id_to_name.get(tactic_id)
        if primary and primary not in order:
            order.append(primary)
        for name in secondaries:
            if name not in order:
                order.append(name)
    return tuple(order)


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


def resolve_redirected_technique_id(tid: str) -> str:
    """Walk ``attack-technique-redirects`` until the ID is no longer remapped.

    Revoked or merged techniques may need one or more hops. The result is the ID MITRE uses in
    the current bundle, so ``matrix`` and ``technique_lookup`` lookups succeed.

    Used by tactic inference (grouping) and by ``build_threat_map_entry`` when validating
    techniques under a known tactic.
    """
    techniques_redirect_map = load_techniques_redirect()
    while tid in techniques_redirect_map:
        tid = techniques_redirect_map[tid]
    return tid


def retain_tactic_display_if_id_and_techniques_still_match(
    tactic_external_id: str, raw_technique_ids: list[str]
) -> str | None:
    """When ``tactic.name`` on disk is stale but ``tactic.id`` is still a bundle tactic id.

    If every resolved technique id still appears under that id's **current** display name in
    ``matrix``, return that name (rename-only). Otherwise return ``None`` so callers infer tactics
    from technique IDs (see ``tactic_assignment_for_technique`` and
    ``secondary_matrix_preferences_for_tactic_id``).

    **Why single-bucket retention:** multi-phase techniques may list several tactics; when the
    whole row still fits the current name for the same ``tactic.id``, keep one row.
    """
    current_name = tactic_id_to_name.get(tactic_external_id)
    if not current_name:
        return None
    bucket = matrix.get(current_name)
    if not bucket:
        return None
    for raw_tid in raw_technique_ids:
        if resolve_redirected_technique_id(raw_tid) not in bucket:
            return None
    return current_name


def tactic_assignment_for_technique(
    resolved_tid: str,
    *,
    row_tactic_external_id: str | None = None,
    secondary_matrix_preferences: tuple[str, ...] = (),
) -> str:
    """Pick one enterprise tactic for ``resolved_tid`` when building ``[[rule.threat]]`` rows.

    **Order:** (1) If ``row_tactic_external_id`` is a live bundle tactic id, use its **current**
    display name when that technique appears in that tactic's matrix column—honors TA0005→Stealth
    (etc.) over lowest-``TAxxxx`` when MITRE lists the technique under multiple phases. (2) Else
    each name in ``secondary_matrix_preferences`` (from
    ``definitions.ATTACK_TACTIC_MIGRATION_SECONDARY_MATRIX_PREFERENCES``).
    (3) Else lowest MITRE tactic id among candidates.

    **Callers:** ``group_technique_ids_by_matrix_tactic`` (and ``choose_canonical_tactic_for_technique``
    for backward compatibility with no row context).

    **Raises:** if the ID is unknown or not placed in any enterprise tactic in the loaded matrix.
    """
    if resolved_tid not in technique_lookup:
        raise ValueError(f"Unknown technique ID: {resolved_tid}")
    candidates = [tactic for tactic, techs in matrix.items() if resolved_tid in techs]
    if not candidates:
        raise ValueError(f"Technique {resolved_tid} is not mapped to any enterprise tactic in the loaded ATT&CK matrix")
    if row_tactic_external_id and row_tactic_external_id in tactic_id_to_name:
        primary_name = tactic_id_to_name[row_tactic_external_id]
        if primary_name in candidates:
            return primary_name
    for preferred in secondary_matrix_preferences:
        if preferred in candidates:
            return preferred
    return min(candidates, key=lambda t: tactics_map[t])


def choose_canonical_tactic_for_technique(resolved_tid: str) -> str:
    """Lowest-``TAxxxx`` tie-break only—no row context. Prefer ``tactic_assignment_for_technique``."""
    return tactic_assignment_for_technique(resolved_tid)


def group_technique_ids_by_matrix_tactic(
    technique_ids: list[str], *, row_tactic_external_id: str | None = None
) -> dict[str, list[str]]:
    """Partition technique IDs by which enterprise tactic they should live under in the current bundle.

    **``row_tactic_external_id``:** when remapping a row whose ``tactic.id`` is still valid in the
    bundle (e.g. ``TA0005``) but ``tactic.name`` is stale, pass it so techniques still mapped under
    that id's current name stay there before tie-break. Secondary preferences come from
    ``secondary_matrix_preferences_for_tactic_id``.
    """
    secondaries: tuple[str, ...] = ()
    if row_tactic_external_id and row_tactic_external_id in tactic_id_to_name:
        secondaries = secondary_matrix_preferences_for_tactic_id(row_tactic_external_id)
    groups: dict[str, list[str]] = defaultdict(list)
    seen: set[str] = set()
    for raw_tid in technique_ids:
        if raw_tid in seen:
            continue
        seen.add(raw_tid)
        resolved = resolve_redirected_technique_id(raw_tid)
        row_id = row_tactic_external_id if row_tactic_external_id in tactic_id_to_name else None
        tactic = tactic_assignment_for_technique(
            resolved,
            row_tactic_external_id=row_id,
            secondary_matrix_preferences=secondaries,
        )
        groups[tactic].append(raw_tid)
    return {t: sorted(set(ids), key=lambda x: (x.split(".")[0], x)) for t, ids in groups.items()}


def rebuild_threat_dicts_from_technique_ids(
    technique_ids: list[str], *, row_tactic_external_id: str | None = None
) -> list[dict[str, Any]]:
    """Produce full MITRE ``[[rule.threat]]``-shaped dicts when the tactic label on disk is unusable.

    **``row_tactic_external_id``:** pass the row's MITRE tactic id when ``tactic.name`` is unknown to
    the bundle but ``tactic.id`` is still valid (see ``group_technique_ids_by_matrix_tactic``).

    **Returns:** empty list if ``technique_ids`` is empty.
    """
    if not technique_ids:
        return []
    groups = group_technique_ids_by_matrix_tactic(
        technique_ids, row_tactic_external_id=row_tactic_external_id
    )
    return [build_threat_map_entry(tactic, *groups[tactic]) for tactic in sorted(groups.keys())]


def build_threat_map_entry(tactic: str, *technique_ids: str) -> dict[str, Any]:
    """Build rule threat map from technique IDs."""
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
        resolved_id = resolve_redirected_technique_id(tid)

        if resolved_id not in matrix[tactic]:
            raise ValueError(f"Technique ID: {resolved_id} does not fall under tactic: {tactic}")

        # sub-techniques
        if "." in resolved_id:
            parent_technique, _ = resolved_id.split(".", 1)
            tech_entries.setdefault(parent_technique, make_entry(parent_technique))
            tech_entries[parent_technique].setdefault("subtechnique", []).append(make_entry(resolved_id))
        else:
            tech_entries.setdefault(resolved_id, make_entry(resolved_id))

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
