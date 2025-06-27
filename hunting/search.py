# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.


from pathlib import Path
from typing import Any

import click

from detection_rules.attack import tactics_map, technique_lookup

from .utils import load_all_toml, load_index_file


class QueryIndex:
    def __init__(self, base_path: Path) -> None:
        """Initialize with the base path and load the index."""
        self.base_path = base_path
        self.hunting_index = load_index_file()
        self.mitre_technique_ids: set[str] = set()
        self.reverse_tactics_map = {v: k for k, v in tactics_map.items()}

    def _process_mitre_filter(self, mitre_filter: tuple[str, ...]) -> None:
        """Process the MITRE filter to gather all matching techniques."""
        for filter_item in mitre_filter:
            if filter_item in self.reverse_tactics_map:
                self._process_tactic_id(filter_item)
            elif filter_item in technique_lookup:
                self._process_technique_id(filter_item)

    def _process_tactic_id(self, filter_item: str) -> None:
        """Helper method to process a tactic ID."""
        tactic_name = self.reverse_tactics_map[filter_item]
        click.echo(f"Found tactic ID {filter_item} (Tactic Name: {tactic_name}). Searching for associated techniques.")

        for tech_id, details in technique_lookup.items():
            kill_chain_phases = details.get("kill_chain_phases", [])
            if any(tactic_name.lower().replace(" ", "-") == phase["phase_name"] for phase in kill_chain_phases):
                self.mitre_technique_ids.add(tech_id)

    def _process_technique_id(self, filter_item: str) -> None:
        """Helper method to process a technique or sub-technique ID."""
        self.mitre_technique_ids.add(filter_item)
        if "." not in filter_item:
            sub_techniques = {
                sub_tech_id for sub_tech_id in technique_lookup if sub_tech_id.startswith(f"{filter_item}.")
            }
            self.mitre_technique_ids.update(sub_techniques)

    def search(
        self, mitre_filter: tuple[str, ...] = (), data_source: str | None = None, keyword: str | None = None
    ) -> list[dict[str, Any]]:
        """Search the index based on MITRE techniques, data source, or keyword."""
        results: list[dict[str, Any]] = []

        # Step 1: If data source is provided, filter by data source first
        if data_source:
            click.echo(f"Filtering by data source: {data_source}")
            results = self._filter_by_data_source(data_source)
            if not results:
                # data source always takes precedence over other filters if provided
                click.echo(f"No matching queries found for data source: {data_source}")
                return results

        # Step 2: If MITRE filter is provided, process the filter
        if mitre_filter:
            click.echo(f"Searching for MITRE techniques: {mitre_filter}")
            self._process_mitre_filter(mitre_filter)
            if results:
                # Filter existing results further by MITRE if data source results already exist
                results = [
                    result for result in results if any(tech in self.mitre_technique_ids for tech in result["mitre"])
                ]
            else:
                # Otherwise, perform a fresh search based on MITRE filter
                results = self._search_index(mitre_filter)

        # Step 3: If keyword is provided, search for it in name, description, and notes
        if keyword:
            click.echo(f"Searching for keyword: {keyword}")
            if results:
                # Filter existing results further by keyword
                results = [result for result in results if self._matches_keyword(result, keyword)]
            else:
                # Perform a fresh search by keyword
                results = self._search_keyword(keyword)

        return self._handle_no_results(results, mitre_filter, data_source, keyword)

    def _search_index(self, mitre_filter: tuple[str, ...] = ()) -> list[dict[str, Any]]:
        """Private method to search the index based on MITRE filter."""
        results: list[dict[str, Any]] = []
        # Load all TOML data for detailed fields
        hunting_content = load_all_toml(self.base_path)

        for hunt_content, file_path in hunting_content:
            query_techniques = hunt_content.mitre
            if mitre_filter and not any(tech in self.mitre_technique_ids for tech in query_techniques):
                continue

            # Prepare the result with full hunt content fields
            matches = hunt_content.__dict__.copy()
            matches["mitre"] = hunt_content.mitre
            matches["data_source"] = hunt_content.integration
            matches["uuid"] = hunt_content.uuid
            matches["path"] = file_path
            results.append(matches)

        return results

    def _search_keyword(self, keyword: str) -> list[dict[str, Any]]:
        """Private method to search description, name, notes, and references fields for a keyword."""
        results: list[dict[str, Any]] = []
        hunting_content = load_all_toml(self.base_path)

        for hunt_content, file_path in hunting_content:
            # Assign blank if notes or references are missing
            notes = "::".join(hunt_content.notes) if hunt_content.notes else ""
            references = "::".join(hunt_content.references) if hunt_content.references else ""

            # Combine name, description, notes, and references for the search
            combined_content = f"{hunt_content.name}::{hunt_content.description}::{notes}::{references}"

            if keyword.lower() in combined_content.lower():
                # Copy hunt_content data and prepare the result
                matches = hunt_content.__dict__.copy()
                matches["mitre"] = hunt_content.mitre
                matches["data_source"] = hunt_content.integration
                matches["uuid"] = hunt_content.uuid
                matches["path"] = file_path
                results.append(matches)

        return results

    def _filter_by_data_source(self, data_source: str) -> list[dict[str, Any]]:
        """Filter the index by data source, checking both the actual files and the index."""
        results: list[dict[str, Any]] = []
        seen_uuids: set[str] = set()  # Track UUIDs to avoid duplicates

        # Load all TOML data for detailed fields
        hunting_content = load_all_toml(self.base_path)

        # Step 1: Check files first by their 'integration' field
        for hunt_content, file_path in hunting_content:
            if data_source in hunt_content.integration and hunt_content.uuid not in seen_uuids:
                # Prepare the result with full hunt content fields
                matches = hunt_content.__dict__.copy()
                matches["mitre"] = hunt_content.mitre
                matches["data_source"] = hunt_content.integration
                matches["uuid"] = hunt_content.uuid
                matches["path"] = file_path
                results.append(matches)
                seen_uuids.add(hunt_content.uuid)

        # Step 2: Check the index for generic data sources (e.g., 'aws', 'linux')
        if data_source in self.hunting_index:
            for query_uuid in self.hunting_index[data_source]:
                if query_uuid not in seen_uuids:
                    # Find corresponding TOML content for this query
                    h = next(((hunt, path) for hunt, path in hunting_content if hunt.uuid == query_uuid), None)
                    if h:
                        hunt_content, path = h
                        # Prepare the result with full hunt content fields
                        matches = hunt_content.__dict__.copy()
                        matches["mitre"] = hunt_content.mitre
                        matches["data_source"] = hunt_content.integration
                        matches["uuid"] = hunt_content.uuid
                        matches["path"] = path
                        results.append(matches)
                        seen_uuids.add(query_uuid)

        return results

    def _matches_keyword(self, result: dict[str, Any], keyword: str) -> bool:
        """Check if the result matches the keyword in name, description, or notes."""
        # Combine relevant fields for keyword search
        notes = "::".join(result.get("notes", [])) if "notes" in result else ""
        references = "::".join(result.get("references", [])) if "references" in result else ""
        combined_content = f"{result['name']}::{result['description']}::{notes}::{references}"

        return keyword.lower() in combined_content.lower()

    def _handle_no_results(
        self,
        results: list[dict[str, Any]],
        mitre_filter: tuple[str, ...] | None = None,
        data_source: str | None = None,
        keyword: str | None = None,
    ) -> list[dict[str, Any]]:
        """Handle cases where no results are found."""
        if not results:
            if mitre_filter and not self.mitre_technique_ids:
                click.echo(f"No MITRE techniques found for the provided filter: {mitre_filter}.")
            if data_source:
                click.echo(f"No matching queries found for data source: {data_source}")
            if keyword:
                click.echo(f"No matches found for keyword: {keyword}")
        return results
