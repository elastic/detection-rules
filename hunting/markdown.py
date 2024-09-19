# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import tomllib
from pathlib import Path

import click
import yaml

from hunting.definitions import (ATLAS_URL, ATTACK_URL,
                                 STATIC_INTEGRATION_LINK_MAP, Hunt)
from hunting.utils import validate_link


def load_toml(contents: str):
    """Load and validate TOML content as Hunt dataclass."""
    toml_dict = tomllib.loads(contents)
    return Hunt(**toml_dict["hunt"])


def load_all_toml(base_path: Path):
    """Load all TOML files from the directory and return a list of Hunt configurations and their paths."""
    hunts = []
    for toml_file in base_path.rglob("*.toml"):
        hunt_config = load_toml(toml_file.read_text(encoding="utf-8"))
        hunts.append((hunt_config, toml_file))
    return hunts


def generate_integration_links(integrations: list[str]) -> list[str]:
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


def convert_toml_to_markdown(hunt_config, file_path: Path):
    """Convert Hunt to Markdown format."""
    markdown = f"# {hunt_config.name}\n\n---\n\n"
    markdown += "## Metadata\n\n"
    markdown += f"- **Author:** {hunt_config.author}\n"
    markdown += f"- **Description:** {hunt_config.description}\n"
    markdown += f"- **UUID:** `{hunt_config.uuid}`\n"
    markdown += f"- **Integration:** {', '.join(generate_integration_links(hunt_config.integration))}\n"
    markdown += f"- **Language:** `{hunt_config.language}`\n".replace("'", "").replace('"', "")
    markdown += f"- **Source File:** [{hunt_config.name}]({(Path('../queries') / file_path.name).as_posix()})\n"
    markdown += "\n## Query\n\n"
    for query in hunt_config.query:
        markdown += f"```sql\n{query}```\n\n"

    if hunt_config.notes:
        markdown += "## Notes\n\n" + "\n".join(f"- {note}" for note in hunt_config.notes)
    if hunt_config.mitre:
        markdown += "\n\n## MITRE ATT&CK Techniques\n\n" + "\n".join(
            f"- [{tech}]({ATLAS_URL if tech.startswith('AML') else ATTACK_URL}"
            f"{tech.replace('.', '/') if tech.startswith('T') else tech})"
            for tech in hunt_config.mitre
        )
    if hunt_config.references:
        markdown += "\n\n## References\n\n" + "\n".join(f"- {ref}" for ref in hunt_config.references)

    markdown += f"\n\n## License\n\n- `{hunt_config.license}`\n"
    return markdown


def process_toml_files(base_path: Path, file_path: Path = None, folder: str = None) -> None:
    """Process TOML files based on the input: a specific file, a folder, or all files."""
    directories = load_index_file(base_path)

    def update_or_add_entry(hunt_config, toml_path):
        folder_name = toml_path.parent.parent.name
        # Search for existing entry by UUID and update it
        for entry in directories.get(folder_name, []):
            if entry['uuid'] == hunt_config.uuid:
                entry.update({
                    'name': hunt_config.name,
                    'path': f"./{toml_path.relative_to(base_path).as_posix()}",  # Ensure path points to TOML
                    'mitre': hunt_config.mitre
                })
                return
        # If no entry is found, add a new one
        directories.setdefault(folder_name, []).append({
            'name': hunt_config.name,
            'path': f"./{toml_path.relative_to(base_path).as_posix()}",  # Point to TOML file
            'uuid': hunt_config.uuid,
            'mitre': hunt_config.mitre
        })

    if file_path:
        if file_path.is_file() and file_path.suffix == '.toml':
            click.echo(f"Processing specific TOML file: {file_path}")
            hunt_config = load_toml(file_path.read_text(encoding="utf-8"))
            markdown_content = convert_toml_to_markdown(hunt_config, file_path)

            # Save Markdown to respective docs folder
            docs_folder = file_path.parent.parent / "docs"
            docs_folder.mkdir(parents=True, exist_ok=True)  # Ensure the folder exists
            markdown_path = docs_folder / f"{file_path.stem}.md"
            markdown_path.write_text(markdown_content, encoding="utf-8")
            print(f"Markdown generated: {markdown_path}")

            # Update or add entry to the directory map (preserving TOML path)
            update_or_add_entry(hunt_config, file_path)

        else:
            raise ValueError(f"The provided path is not a valid TOML file: {file_path}")

    elif folder:
        folder_path = base_path / folder / "queries"
        docs_folder = base_path / folder / "docs"
        folder_path.mkdir(parents=True, exist_ok=True)
        docs_folder.mkdir(parents=True, exist_ok=True)

        if folder_path.is_dir() and docs_folder.is_dir():
            click.echo(f"Processing all TOML files in folder: {folder_path}")
            toml_files = folder_path.rglob("*.toml")
        else:
            raise ValueError(f"Queries folder {folder_path} or docs folder {docs_folder} does not exist.")
    else:
        click.echo("Processing all TOML files in the base directory and subfolders.")
        toml_files = base_path.rglob("queries/*.toml")

    if not file_path:
        for toml_file in toml_files:
            hunt_config = load_toml(toml_file.read_text(encoding="utf-8"))
            markdown_content = convert_toml_to_markdown(hunt_config, toml_file)

            docs_folder = toml_file.parent.parent / "docs"
            docs_folder.mkdir(parents=True, exist_ok=True)  # Ensure the folder exists
            markdown_path = docs_folder / f"{toml_file.stem}.md"
            markdown_path.write_text(markdown_content, encoding="utf-8")
            print(f"Markdown generated: {markdown_path}")

            # Update or add entry to the directory map (preserving TOML path)
            update_or_add_entry(hunt_config, toml_file)

    # Save the updated index.yml
    save_index_file(base_path, directories)

    # Update the index.md file with all the new entries
    update_index_file(base_path)


def load_index_file(base_path: Path) -> dict:
    """Load the index.yml file and return its contents as a dictionary."""
    index_file = base_path / "index.yml"
    if index_file.exists():
        with open(index_file, 'r') as f:
            return yaml.safe_load(f) or {}
    return {}


def save_index_file(base_path: Path, directories: dict) -> None:
    """Save the updated index.yml file."""
    index_file = base_path / "index.yml"
    with open(index_file, 'w') as f:
        yaml.safe_dump(directories, f, default_flow_style=False)
    print(f"Index YAML updated at: {index_file}")


def update_index_file(base_path: Path) -> None:
    """Update the index.md file based on the entries in index.yml."""
    index_file = base_path / "index.yml"
    index_content = "# List of Available Queries\n\nHere are the queries currently available:\n"

    if not index_file.exists():
        print(f"No index.yml found at {index_file}. Skipping index.md update.")
        return

    with open(index_file, 'r') as f:
        directories = yaml.safe_load(f)

    for folder, files in sorted(directories.items()):
        index_content += f"\n\n## {folder}\n"
        for file_info in sorted(files, key=lambda x: x['name']):
            # Generate path to .md file in 'docs' folder
            md_path = file_info['path'].replace('queries', 'docs').replace('.toml', '.md')
            index_content += f"- [{file_info['name']}]({md_path}) (ES|QL)"
            index_content += "\n"

    # Write the updated index to index.md
    index_md_path = base_path / "index.md"
    index_md_path.write_text(index_content, encoding="utf-8")
    print(f"Index Markdown updated at: {index_md_path}")


def update_index_yml(base_path: Path) -> None:
    """Update index.yml based on the current TOML files."""
    directories = load_index_file(base_path)  # Load the existing index.yml data

    # Load all TOML files recursively
    toml_files = base_path.rglob("queries/*.toml")  # Find all TOML files in the 'queries' directory

    for toml_file in toml_files:
        # Load TOML and extract hunt configuration
        hunt_config = load_toml(toml_file.read_text(encoding="utf-8"))  # Parse the TOML file

        folder_name = toml_file.parent.parent.name  # Determine the folder (platform, integration, etc.)

        # Check for existing entry with the same UUID and update it
        existing_entry = next((entry for entry in directories.get(folder_name, [])
                               if entry['uuid'] == hunt_config.uuid), None)

        if existing_entry:
            # Update the existing entry
            existing_entry.update({
                'name': hunt_config.name,
                'path': f"./{toml_file.relative_to(base_path).as_posix()}",  # Ensure the path links to TOML file
                'mitre': hunt_config.mitre
            })
        else:
            # Add a new entry if the UUID does not exist
            directories.setdefault(folder_name, []).append({
                'name': hunt_config.name,
                'path': f"./{toml_file.relative_to(base_path).as_posix()}",  # Link to the TOML file
                'uuid': hunt_config.uuid,
                'mitre': hunt_config.mitre
            })

    # Save the updated index.yml
    save_index_file(base_path, directories)
