# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.


from pathlib import Path

import click
from detection_rules.attack import tactics_map, technique_lookup

from .utils import load_index_file


class QueryIndex:
    def __init__(self, base_path: Path):
        """Initialize with the base path and load the index."""
        self.base_path = base_path
        self.hunting_index = load_index_file()
        self.mitre_technique_ids = set()
        self.reverse_tactics_map = {v: k for k, v in tactics_map.items()}

    def process_mitre_filter(self, mitre_filter: tuple):
        """Process the MITRE filter to gather all matching techniques."""
        for filter_item in mitre_filter:
            if filter_item in self.reverse_tactics_map:
                self._process_tactic_id(filter_item)
            elif filter_item in technique_lookup:
                self._process_technique_id(filter_item)

    def _process_tactic_id(self, filter_item):
        """Helper method to process a tactic ID."""
        tactic_name = self.reverse_tactics_map[filter_item]
        click.echo(f"Found tactic ID {filter_item} (Tactic Name: {tactic_name}). Searching for associated techniques.")

        for tech_id, details in technique_lookup.items():
            kill_chain_phases = details.get('kill_chain_phases', [])
            if any(tactic_name.lower().replace(' ', '-') == phase['phase_name'] for phase in kill_chain_phases):
                self.mitre_technique_ids.add(tech_id)

    def _process_technique_id(self, filter_item):
        """Helper method to process a technique or sub-technique ID."""
        self.mitre_technique_ids.add(filter_item)
        if '.' not in filter_item:
            sub_techniques = {
                sub_tech_id for sub_tech_id in technique_lookup
                if sub_tech_id.startswith(f"{filter_item}.")
            }
            self.mitre_technique_ids.update(sub_techniques)

    def search(self, mitre_filter: tuple = (), data_source: str = None) -> list:
        """Search the index based on MITRE techniques or data source."""
        # Process the MITRE filter
        if mitre_filter:
            self.process_mitre_filter(mitre_filter)

        # Perform search and return results
        return self._search_index(mitre_filter, data_source)

    def _search_index(self, mitre_filter: tuple, data_source: str) -> list:
        """Private method to search the index based on filters."""
        results = []

        for folder, queries in self.hunting_index.items():
            if data_source and folder != data_source:
                continue

            for uuid, query in queries.items():
                query_techniques = query.get('mitre', [])
                if mitre_filter and not any(tech in self.mitre_technique_ids for tech in query_techniques):
                    continue

                query_with_data_source = query.copy()
                query_with_data_source['data_source'] = folder
                query_with_data_source['uuid'] = uuid
                results.append(query_with_data_source)

        return self._handle_no_results(results, mitre_filter, data_source)

    def _handle_no_results(self, results, mitre_filter, data_source):
        """Handle cases where no results are found."""
        if not results:
            if mitre_filter and not self.mitre_technique_ids:
                click.echo(f"No MITRE techniques found for the provided filter: {mitre_filter}.")
            if data_source:
                click.echo(f"No matching queries found for data source: {data_source}")
        return results
