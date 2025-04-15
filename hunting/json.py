# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path
import click
from .definitions import ATLAS_URL, ATTACK_URL, STATIC_INTEGRATION_LINK_MAP, Hunt
from .utils import load_index_file, load_toml, save_index_file, validate_link

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

        self.update_or_add_entry(hunt_config, file_path)

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

    def convert_toml_to_json(self, hunt_config: Hunt, file_path: Path) -> dict:
        """Convert a Hunt configuration to JSON format."""
        json_data = {
            "name": hunt_config.name,
            "metadata": {
                "author": hunt_config.author,
                "description": hunt_config.description,
                "uuid": hunt_config.uuid,
                "integration": hunt_config.integration,
                "language": str(hunt_config.language).replace("'", "").replace('"', ""),
                "source_file": {
                    "name": hunt_config.name,
                    "path": (Path('../queries') / file_path.name).as_posix()
                }
            },
            "queries": hunt_config.query,
            "notes": hunt_config.notes if hunt_config.notes else [],
            "mitre_techniques": hunt_config.mitre,
            "references": hunt_config.references if hunt_config.references else [],
            "license": hunt_config.license
        }
        
        return json_data

    def save_json(self, json_path: Path, content: dict) -> None:
        """Save the JSON content to a file."""
        import json
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(content, f, indent=2, ensure_ascii=False)
        click.echo(f"JSON generated: {json_path}")

    def update_or_add_entry(self, hunt_config: Hunt, toml_path: Path) -> None:
        """Update or add the entry for a TOML file in the hunting index."""
        folder_name = toml_path.parent.parent.name
        uuid = hunt_config.uuid

        entry = {
            'name': hunt_config.name,
            'path': f"./{toml_path.relative_to(self.base_path).as_posix()}",
            'mitre': hunt_config.mitre
        }

        if folder_name not in self.hunting_index:
            self.hunting_index[folder_name] = {uuid: entry}
        else:
            self.hunting_index[folder_name][uuid] = entry

        save_index_file(self.base_path, self.hunting_index)

    def create_json_folder(self, file_path: Path) -> Path:
        """Create the docs folder if it doesn't exist and return the path."""
        json_folder = file_path.parent.parent / "json"
        json_folder.mkdir(parents=True, exist_ok=True)
        return json_folder

    def generate_integration_links(self, integrations: list[str]) -> list[str]:
        """Generate integration links for the documentation."""
        base_url = 'https://docs.elastic.co/integrations'
        generated = []
        for integration in integrations:
            if integration in STATIC_INTEGRATION_LINK_MAP:
                link_str = STATIC_INTEGRATION_LINK_MAP[integration]
            else:
                link_str = integration.replace('.', '/')
            link = f'{base_url}/{link_str}'
            validate_link(link)
            generated.append(f'[{integration}]({link})')
        return generated

    def update_index_json(self) -> None:
        """Update the index.json file based on the entries in index.yml."""
        import json
        index_file = self.base_path / "index.yml"
        
        if not index_file.exists():
            click.echo(f"No index.yml found at {index_file}. Skipping index.json update.")
            return
            
        index_json = {"categories": []}

        for folder, files in sorted(self.hunting_index.items()):
            category = {
                "name": folder,
                "files": []
            }
            
            for file_info in sorted(files.values(), key=lambda x: x['name']):
                json_path = file_info['path'].replace('queries', 'docs').replace('.toml', '.json')
                category["files"].append({
                    "name": file_info['name'],
                    "path": json_path,
                    "type": "ES|QL"
                })
                
            index_json["categories"].append(category)

        index_json_path = self.base_path / "index.json"
        with open(index_json_path, 'w', encoding='utf-8') as f:
            json.dump(index_json, f, indent=2, ensure_ascii=False)
        click.echo(f"Index JSON updated at: {index_json_path}")