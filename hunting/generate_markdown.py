# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Lightweight builtin toml-markdown converter."""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

HUNTING_DIR = Path(__file__).parent


@dataclass
class Hunt:
    """Dataclass to represent a hunt."""

    author: str
    integration: str
    uuid: str
    name: str
    language: str
    query: str
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


def convert_toml_to_markdown(hunt_config: Hunt, file_path: Path) -> str:
    """Convert Hunt to Markdown format."""
    markdown = f"# {hunt_config.name}\n\n---\n\n"
    markdown += "## Metadata\n\n"
    markdown += f"- **Author:** {hunt_config.author}\n"
    markdown += f"- **UUID:** `{hunt_config.uuid}`\n"
    markdown += f"- **Integration:** `{hunt_config.integration}`\n"
    markdown += f"- **Language:** `{hunt_config.language}`\n\n"
    markdown += "## Query\n\n"
    markdown += f"```sql\n{hunt_config.query}```\n\n"
    if hunt_config.notes:
        markdown += "## Notes\n\n" + "\n".join(f"- {note}" for note in hunt_config.notes)
    if hunt_config.mitre:
        markdown += "\n## MITRE ATT&CK Techniques\n\n" + "\n".join(
            f"- [{tech}](https://atlas.mitre.org/techniques/{tech})\n" for tech in hunt_config.mitre
        )
    if hunt_config.references:
        markdown += "\n## References\n\n" + "\n".join(f"- {ref}" for ref in hunt_config.references)
        markdown += f"\n- [{hunt_config.name}]({Path('../queries') / file_path.name})"
    return markdown


def process_toml_files(base_path: Path) -> None:
    """Process all TOML files in the directory recursively and convert them to Markdown."""
    hunts = load_all_toml(base_path)
    for hunt_config, toml_file in hunts:
        markdown_content = convert_toml_to_markdown(hunt_config, toml_file)
        markdown_path = toml_file.parent.parent / "docs" / f"{toml_file.stem}.md"
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(markdown_content, encoding="utf-8")
        print(f"Markdown generated: {markdown_path}")


if __name__ == "__main__":
    process_toml_files(HUNTING_DIR)
