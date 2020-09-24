# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Mitre attack info."""

import json
import os
import requests
from collections import OrderedDict

from .semver import Version
from .utils import get_etc_path, get_etc_glob_path, read_gzip, gzip_compress

PLATFORMS = ['Windows', 'macOS', 'Linux']
tactics_map = {}


def get_attack_file_path():
    pattern = 'attack-v*.json.gz'
    attack_file = get_etc_glob_path(pattern)
    if len(attack_file) != 1:
        raise FileNotFoundError(f'Missing required {pattern} file')
    return attack_file[0]


def load_attack_gz():
    return json.loads(read_gzip(get_attack_file_path()))


attack = load_attack_gz()

technique_lookup = {}
revoked = {}

for item in attack["objects"]:
    if item["type"] == "x-mitre-tactic":
        tactics_map[item['name']] = item['external_references'][0]['external_id']

    if item["type"] == "attack-pattern" and item["external_references"][0]['source_name'] == 'mitre-attack':
        technique_id = item['external_references'][0]['external_id']
        technique_lookup[technique_id] = item

        if item.get('revoked'):
            revoked[technique_id] = item

tactics = list(tactics_map)
matrix = {tactic: [] for tactic in tactics}
no_tactic = []
attack_tm = 'ATT&CK\u2122'


# Enumerate over the techniques and build the matrix back up
for technique_id, technique in sorted(technique_lookup.items(), key=lambda kv: kv[1]['name'].lower()):
    kill_chain = technique.get('kill_chain_phases')
    if kill_chain:
        for tactic in kill_chain:
            tactic_name = next(t for t in tactics if tactic['kill_chain_name'] == 'mitre-attack' and t.lower() == tactic['phase_name'].replace("-", " "))  # noqa: E501
            matrix[tactic_name].append(technique_id)
        else:
            no_tactic.append(technique_id)

for tactic in matrix:
    matrix[tactic].sort(key=lambda tid: technique_lookup[tid]['name'].lower())


technique_lookup = OrderedDict(sorted(technique_lookup.items()))
techniques = sorted({v['name'] for k, v in technique_lookup.items()})


def refresh_attack_data(save=True):
    """Refresh ATT&CK data from Mitre."""
    attack_path = get_attack_file_path()
    filename, _, _ = os.path.basename(attack_path).rsplit('.', 2)

    def get_version_from_tag(name, pattern='att&ck-v'):
        _, version = name.lower().split(pattern, 1)
        return version

    current_version = get_version_from_tag(filename, 'attack-v')

    r = requests.get('https://api.github.com/repos/mitre/cti/tags')
    r.raise_for_status()
    releases = [t for t in r.json() if t['name'].startswith('ATT&CK-v')]
    latest_release = max(releases, key=lambda release: Version(get_version_from_tag(release['name'])))
    release_name = latest_release['name']
    latest_version = get_version_from_tag(release_name)

    if current_version >= latest_version:
        print(f'No versions newer than the current detected: {current_version}')
        return

    download = f'https://raw.githubusercontent.com/mitre/cti/{release_name}/enterprise-attack/enterprise-attack.json'
    r = requests.get(download)
    r.raise_for_status()
    attack_data = r.json()
    compressed = gzip_compress(json.dumps(attack_data, sort_keys=True))

    if save:
        new_path = get_etc_path(f'attack-v{latest_version}.json.gz')
        with open(new_path, 'wb') as f:
            f.write(compressed)

        os.remove(attack_path)
        print(f'Replaced file: {attack_path} with {new_path}')

    return attack_data, compressed


def build_threat_map_entry(tactic: str, *technique_ids: str) -> dict:
    """Build rule threat map from technique IDs."""
    url_base = 'https://attack.mitre.org/{type}/{id}/'
    tactic_id = tactics_map[tactic]
    entry = {
        'framework': 'MITRE ATT&CK',
        'technique': [
            {
                'id': tid,
                'name': technique_lookup[tid]['name'],
                'reference': url_base.format(type='techniques', id=tid)
            } for tid in technique_ids
        ],
        'tactic': {
            'id': tactic_id,
            'name': tactic,
            'reference': url_base.format(type='tactics', id=tactic_id)
        }
    }

    return entry


def update_threat_map(rule_threat_map):
    """Update rule map techniques to reflect changes from ATT&CK."""
    for entry in rule_threat_map:
        for tech in entry['technique']:
            tech['name'] = technique_lookup[tech['id']]['name']
