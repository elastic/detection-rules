# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from dataclasses import asdict
import datetime
import json
from pathlib import Path, PosixPath
import click
from .definitions import Hunt
from .utils import load_index_file, load_toml
import re

now = datetime.datetime.now()
timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
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
        json_content = self.convert_toml_to_json(hunt_config, file_path)

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

    def convert_toml_to_json(self, hunt_config: Hunt, path: str) -> str:
        """Convert a Hunt configuration to JSON format."""
        hunt_config_dict = asdict(hunt_config)
        hunt_config_dict["queries"] = self.format_queries(hunt_config_dict["query"])
        hunt_config_dict.pop("query")
        hunt_config_dict["category"] = self.path_to_category(path)
        hunt_config_dict["@timestamp"] = timestamp
        return json.dumps(hunt_config_dict, indent=4)
    
    def path_to_category(self, path: PosixPath) -> str:
        """
        Convert a file path to a category string.
        
        Args:
            path (str): The file path.
            
        Returns:
            str: The category string derived from the file path.
        """
        # category is the direcory the queries are in
        # e.g. "hunting/winodws/queries" -> "windows"
        
        # Get the path parts
        parts = path.parts
        # Check if the last part is "queries"
        if "queries" in parts:
            # Get the index of "queries" in the path
            queries_index = parts.index("queries")
            # If "queries" exists and there's a part before it, return that as the category
            if queries_index > 0:
                return parts[queries_index - 1]
        
        # Default fallback: return the parent directory name
        return path.parent.name
        
    
    @staticmethod
    def extract_indices_from_esql(esql_query):
        """
        Extract indices from an ESQL query.
        
        Args:
            esql_query (str): The ESQL query.
            
        Returns:
            list: A list of indices found in the query.
        """
        # Handle SELECT statements that start with SELECT instead of FROM
        if esql_query.strip().upper().startswith('SELECT'):
            # Find the FROM keyword after SELECT
            match = re.search(r'FROM\s+([^\s|,;\n]+)', esql_query, re.IGNORECASE)
            if match:
                return [match.group(1).strip()]
        
        # For queries that start with FROM directly
        # Normalize whitespace by removing extra spaces and newlines
        normalized_query = ' '.join(esql_query.split())
        
        # Check if the query starts with "from"
        if not normalized_query.lower().startswith('from '):
            return []
        
        # Extract the part after "from" and before the first pipe (|)
        # First remove any inline comments with //
        cleaned_query = re.sub(r'//.*$', '', normalized_query, flags=re.MULTILINE)
        # Extract text after "from" keyword, then split by pipe, newline, or WHERE
        from_part = cleaned_query[5:]  # Skip the "from" prefix
        # Find the first occurrence of pipe, newline, or "WHERE" (case insensitive)
        pipe_pos = from_part.find('|')
        newline_pos = from_part.find('\n')
        where_pos = re.search(r'WHERE', from_part, re.IGNORECASE)
        where_pos = where_pos.start() if where_pos else -1
        
        # Find the earliest delimiter (pipe, newline, or WHERE)
        positions = [pos for pos in [pipe_pos, newline_pos, where_pos] if pos >= 0]
        end_pos = min(positions) if positions else len(from_part)
        
        from_part = from_part[:end_pos].strip()
        
        # Split by commas if multiple indices are provided
        indices = [index.strip() for index in from_part.split(',')]
        
        return indices
    
    def remove_comments_and_blank_lines(self, esql_query):
        """
        Remove comments and blank lines from an ESQL query.
        
        Args:
            esql_query (str): The ESQL query.
            
        Returns:
            str: The cleaned ESQL query.
        """
        # Remove block comments (/* ... */)
        cleaned_query = re.sub(r'/\*.*?\*/', '', esql_query, flags=re.DOTALL)
        
        # Remove line comments and blank lines
        result = []
        for line in cleaned_query.splitlines():
            # Skip comment lines and blank lines
            if not line.strip().startswith("//") and line.strip():
                result.append(line)
        
        return "\n".join(result)
    
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
                "cleaned_query": self.remove_comments_and_blank_lines(query)
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
