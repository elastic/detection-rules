# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.


from pathlib import Path

import click
import yaml

from detection_rules.attack import tactics_map, technique_lookup


def search_index(base_path: Path, mitre_filter: tuple = (), data_source: str = None) -> list:
    """Search the index for queries matching the MITRE techniques, tactic, or data_source."""

    # Load index.yml
    index_file = base_path / "index.yml"
    if not index_file.exists():
        click.echo(f"No index.yml found at {index_file}.")
        return []

    with open(index_file, 'r') as f:
        hunting_index = yaml.safe_load(f)

    # Initialize a set for MITRE technique IDs
    mitre_technique_ids = set()
    reverse_tactics_map = {v: k for k, v in tactics_map.items()}

    # Process the MITRE filter (could be tactic ID, technique ID, or sub-technique ID)
    for filter_item in mitre_filter:
        if filter_item in reverse_tactics_map:
            # Retrieve the tactic name using the tactic ID
            tactic_name = reverse_tactics_map[filter_item]
            click.echo(f"Found tactic ID {filter_item} (Tactic Name: {tactic_name}). Searching for associated techniques.")  # noqa: E501

            # Now find techniques that have this tactic in the kill_chain_phases
            for tech_id, details in technique_lookup.items():
                kill_chain_phases = details.get('kill_chain_phases', [])
                # Match based on phase_name, ensuring it's lowercased and without hyphens
                if any(tactic_name.lower().replace(' ', '-') == phase['phase_name'] for phase in kill_chain_phases):
                    mitre_technique_ids.add(tech_id)

        elif filter_item in technique_lookup:
            # Add the technique or sub-technique ID directly
            mitre_technique_ids.add(filter_item)

            # Include all sub-techniques if the filter is a parent technique (e.g., T1078)
            if '.' not in filter_item:
                # Find all sub-techniques of the parent technique
                sub_techniques = {
                    sub_tech_id for sub_tech_id in technique_lookup
                    if sub_tech_id.startswith(f"{filter_item}.")
                }
                mitre_technique_ids.update(sub_techniques)

    # Search the index for queries that match the MITRE techniques and data_source
    results = []
    for folder, queries in hunting_index.items():
        # If a data_source is specified, filter by data_source
        if data_source and folder != data_source:
            continue

        for uuid, query in queries.items():  # Adjust to iterate over the dictionary
            query_techniques = query.get('mitre', [])
            # Match queries that contain at least one technique from the filtered set
            if not mitre_technique_ids or any(tech in mitre_technique_ids for tech in query_techniques):
                # Add the data_source (which is the folder or top-level object) to each result
                query_with_data_source = query.copy()
                query_with_data_source['data_source'] = folder  # Add data_source to the query result
                results.append(query_with_data_source)

    return results