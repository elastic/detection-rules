# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Mitre attack info."""
# from: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

from .utils import load_etc_dump

TACTICS_MAP = {
    'Initial Access': 'TA0001',
    'Persistence': 'TA0003',
    'Privilege Escalation': 'TA0004',
    'Defense Evasion': 'TA0005',
    'Credential Access': 'TA0006',
    'Discovery': 'TA0007',
    'Lateral Movement': 'TA0008',
    'Execution': 'TA0002',
    'Collection': 'TA0009',
    'Exfiltration': 'TA0011',
    'Command and Control': 'TA0010',
    'Impact': 'TA0040'
}
TACTICS = list(TACTICS_MAP)
PLATFORMS = ['Windows', 'macOS', 'Linux']

attack = load_etc_dump('attack.json')

technique_lookup = {}

for item in attack["objects"]:
    if item["type"] == "attack-pattern" and item["external_references"][0]['source_name'] == 'mitre-attack':
        technique_id = item['external_references'][0]['external_id']
        technique_lookup[technique_id] = item

matrix = {tactic: [] for tactic in TACTICS}
attack_tm = 'ATT&CK\u2122'


# Enumerate over the techniques and build the matrix back up
for technique_id, technique in sorted(technique_lookup.items(), key=lambda kv: kv[1]['name'].lower()):
    for platform in technique['x_mitre_platforms']:
        if any(platform.startswith(p) for p in PLATFORMS):
            break
    else:
        continue

    for tactic in technique['kill_chain_phases']:
        tactic_name = next(t for t in TACTICS if tactic['kill_chain_name'] == 'mitre-attack' and t.lower() == tactic['phase_name'].replace("-", " "))  # noqa: E501
        matrix[tactic_name].append(technique_id)

for tactic in matrix:
    matrix[tactic].sort(key=lambda tid: technique_lookup[tid]['name'].lower())


TECHNIQUES = {v['name'] for k, v in technique_lookup.items()}


def build_threat_map_entry(tactic: str, *technique_ids: str) -> dict:
    """Build rule threat map from technique IDs."""
    url_base = 'https://attack.mitre.org/{type}/{id}/'
    tactic_id = TACTICS_MAP[tactic]
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
