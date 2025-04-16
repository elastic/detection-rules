# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from dataclasses import asdict
import json
from pathlib import Path
import click
from .definitions import Hunt
from .utils import load_index_file, load_toml

class JSONGenerator:
    """Class to generate or update JSON documentation from TOML or YAML files."""
    def __init__(self, base_path: Path):
        """Initialize with the base path and load the hunting index."""
        self.base_path = base_path
        self.hunting_index = load_index_file()

    def process_file(self, file_path: Path) -> None:
        """Process a single TOML file and generate its JSON representation."""
        if not file_path.is_file() or file_path.suffix != '.toml':
            raise ValueError(f"The provided path is not a valid TOML file: {file_path}")

        click.echo(f"Processing specific TOML file: {file_path}")
        hunt_config = load_toml(file_path)
        json_content = self.convert_toml_to_json(hunt_config)

        json_folder = self.create_json_folder(file_path)
        json_path = json_folder / f"{file_path.stem}.json"
        self.save_json(json_path, json_content)

    def process_folder(self, folder: str) -> None:
        """Process all TOML files in a specified folder and generate their JSON representations."""
        folder_path = self.base_path / folder / "queries"
        json_folder = self.base_path / folder / "docs"

        if not folder_path.is_dir() or not json_folder.is_dir():
            raise ValueError(f"Queries folder {folder_path} or docs folder {json_folder} does not exist.")

        click.echo(f"Processing all TOML files in folder: {folder_path}")
        toml_files = folder_path.rglob("*.toml")

        for toml_file in toml_files:
            self.process_file(toml_file)

    def process_all_files(self) -> None:
        """Process all TOML files in the base directory and subfolders."""
        click.echo("Processing all TOML files in the base directory and subfolders.")
        toml_files = self.base_path.rglob("queries/*.toml")

        for toml_file in toml_files:
            self.process_file(toml_file)

    def convert_toml_to_json(self, hunt_config: Hunt) -> str:
        """Convert a Hunt configuration to JSON format."""
        return json.dumps(asdict(hunt_config), indent=4)
    
    @staticmethod
    def extract_indices_from_esql(esql_query):
        """
        Extract indices from an ESQL query.
        
        Args:
            esql_query (str): The ESQL query.
            
        Returns:
            list: A list of indices found in the query.
        """
        # Normalize whitespace by removing extra spaces and newlines
        normalized_query = ' '.join(esql_query.split())
        
        # Check if the query starts with "from"
        if not normalized_query.lower().startswith('from '):
            return []
        
        # Extract the part after "from" and before the first pipe (|)
        from_part = normalized_query[5:].split('|', 1)[0].strip()
        
        # Split by commas if multiple indices are provided
        indices = [index.strip() for index in from_part.split(',')]
        
        return indices
    
    def format_queries(self, queries: list[str]) -> list[dict]:
        """
        Format the queries for JSON output.
        
        Args:
            queries (list[str]): List of ESQL queries.
        Returns:
            list[dict]: List of dictionaries containing the query and its indices.
        """
        formatted_queries = []

        for query in queries:
            formatted_queries.append({
                "query": query,
                "indices": self.extract_indices_from_esql(query),
            })

        return formatted_queries

    def save_json(self, json_path: Path, content: str) -> None:
        """Save the JSON content to a file."""
        with open(json_path, 'w', encoding='utf-8') as f:
            f.write(content)
        click.echo(f"JSON generated: {json_path}")

    def create_json_folder(self, file_path: Path) -> Path:
        """Create the docs folder if it doesn't exist and return the path."""
        json_folder = file_path.parent.parent / "json"
        json_folder.mkdir(parents=True, exist_ok=True)
        return json_folder
