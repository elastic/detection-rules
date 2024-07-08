# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Lightweight builtin toml-markdown converter."""

import os
import tomllib
import urllib3
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

HUNTING_DIR = Path(__file__).parent
ATLAS_URL = "https://atlas.mitre.org/techniques/"
ATTACK_URL = "https://attack.mitre.org/techniques/"

# the standard link takes `integration.package` and converts the link to `integration/package`, however, there are
# some exceptions such as `aws_bedrock.invocation` which should be linked to `aws_bedrock` instead
# https://docs.elastic.co/integrations/aws_bedrock
STATIC_INTEGRATION_LINK_MAP = {
    'aws_bedrock.invocation': 'aws_bedrock'
}


@dataclass
class Hunt:
    """Dataclass to represent a hunt."""

    author: str
    description: str
    integration: List[str]
    uuid: str
    name: str
    language: List[str]
    license: str
    query: List[str]
    notes: Optional[List[str]] = field(default_factory=list)
    mitre: Optional[List[str]] = field(default_factory=list)
    references: Optional[List[str]] = field(default_factory=list)


def load_toml(contents: str) -> Hunt:
    """Load and validate TOML content as Hunt dataclass."""
    toml_dict = tomllib.loads(contents)
    return Hunt(**toml_dict["hunt"])


def load_all_toml(base_path: Path) -> List[tuple[Hunt, Path]]:
    """Load all TOML files from the directory and return a list of Hunt configurations and their paths."""
    hunts = []
    for toml_file in base_path.rglob("*.toml"):
        hunt_config = load_toml(toml_file.read_text())
        hunts.append((hunt_config, toml_file))
    return hunts


def validate_link(link: str):
    """Validate and return the link."""
    http = urllib3.PoolManager()
    response = http.request('GET', link)
    if response.status != 200:
        raise ValueError(f"Invalid link: {link}")


def generate_integration_links(integrations: List[str]) -> List[str]:
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


def convert_toml_to_markdown(hunt_config: Hunt, file_path: Path) -> str:
    """Convert Hunt to Markdown format."""
    markdown = f"# {hunt_config.name}\n\n---\n\n"
    markdown += "## Metadata\n\n"
    markdown += f"- **Author:** {hunt_config.author}\n"
    markdown += f"- **Description:** {hunt_config.description}\n"
    markdown += f"- **UUID:** `{hunt_config.uuid}`\n"
    markdown += f"- **Integration:** {', '.join(generate_integration_links(hunt_config.integration))}\n"
    markdown += f"- **Language:** `{hunt_config.language}`\n".replace("'", "").replace('"', "")
    markdown += f"- **Source File:** [{hunt_config.name}]({Path('../queries') / file_path.name})"
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


def process_toml_files(base_path: Path) -> None:
    """Process all TOML files in the directory recursively and convert them to Markdown."""
    index_content = "# List of Available Queries\n\nHere are the queries currently available:"
    directories = {}

    for platform_dir in base_path.iterdir():
        if platform_dir.is_dir():
            queries_dir = platform_dir / "queries"
            docs_dir = platform_dir / "docs"
            hunts = load_all_toml(queries_dir)

            for hunt_config, toml_file in hunts:
                markdown_content = convert_toml_to_markdown(hunt_config, toml_file)
                markdown_path = docs_dir / toml_file.relative_to(queries_dir).with_suffix(".md")
                markdown_path.parent.mkdir(parents=True, exist_ok=True)
                markdown_path.write_text(markdown_content, encoding="utf-8")
                print(f"Markdown generated: {markdown_path}")
                relative_path = os.path.normpath(markdown_path.relative_to(base_path))
                folder_name = platform_dir.name
                directories.setdefault(folder_name, []).append((relative_path, hunt_config.name, hunt_config.language))

    # Build index content
    for folder, files in sorted(directories.items()):
        index_content += f"\n\n## {folder}\n"
        for file_path, rule_name, language in sorted(files):
            index_path = f"./{str(file_path).replace(os.path.sep, '/')}"
            index_content += f"- [{rule_name}]({index_path}) ({', '.join(language)})\n"

    # Write the index file at the base directory level
    index_path = base_path / "index.md"
    index_path.write_text(index_content, encoding="utf-8")
    print(f"Index Markdown generated at: {index_path}")


if __name__ == "__main__":
    process_toml_files(HUNTING_DIR)
