# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path

import click

from .definitions import ATLAS_URL, ATTACK_URL, STATIC_INTEGRATION_LINK_MAP, Hunt
from .utils import load_index_file, load_toml, save_index_file, validate_link


class MarkdownGenerator:
    """Class to generate or update Markdown documentation from TOML or YAML files."""

    def __init__(self, base_path: Path) -> None:
        """Initialize with the base path and load the hunting index."""
        self.base_path = base_path
        self.hunting_index = load_index_file()

    def process_file(self, file_path: Path) -> None:
        """Process a single TOML file and generate its Markdown representation."""
        if not file_path.is_file() or file_path.suffix != ".toml":
            raise ValueError(f"The provided path is not a valid TOML file: {file_path}")

        click.echo(f"Processing specific TOML file: {file_path}")
        hunt_config = load_toml(file_path)
        markdown_content = self.convert_toml_to_markdown(hunt_config, file_path)

        docs_folder = self.create_docs_folder(file_path)
        markdown_path = docs_folder / f"{file_path.stem}.md"
        self.save_markdown(markdown_path, markdown_content)

        self.update_or_add_entry(hunt_config, file_path)

    def process_folder(self, folder: str) -> None:
        """Process all TOML files in a specified folder and generate their Markdown representations."""
        folder_path = self.base_path / folder / "queries"
        docs_folder = self.base_path / folder / "docs"

        if not folder_path.is_dir() or not docs_folder.is_dir():
            raise ValueError(f"Queries folder {folder_path} or docs folder {docs_folder} does not exist.")

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

    def convert_toml_to_markdown(self, hunt_config: Hunt, file_path: Path) -> str:
        """Convert a Hunt configuration to Markdown format."""
        markdown = f"# {hunt_config.name}\n\n---\n\n"
        markdown += "## Metadata\n\n"
        markdown += f"- **Author:** {hunt_config.author}\n"
        markdown += f"- **Description:** {hunt_config.description}\n"
        markdown += f"- **UUID:** `{hunt_config.uuid}`\n"
        markdown += f"- **Integration:** {', '.join(self.generate_integration_links(hunt_config.integration))}\n"
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

    def save_markdown(self, markdown_path: Path, content: str) -> None:
        """Save the Markdown content to a file."""
        _ = markdown_path.write_text(content, encoding="utf-8")
        click.echo(f"Markdown generated: {markdown_path}")

    def update_or_add_entry(self, hunt_config: Hunt, toml_path: Path) -> None:
        """Update or add the entry for a TOML file in the hunting index."""
        folder_name = toml_path.parent.parent.name
        uuid = hunt_config.uuid

        entry = {
            "name": hunt_config.name,
            "path": f"./{toml_path.resolve().relative_to(self.base_path).as_posix()}",
            "mitre": hunt_config.mitre,
        }

        if folder_name not in self.hunting_index:
            self.hunting_index[folder_name] = {uuid: entry}
        else:
            self.hunting_index[folder_name][uuid] = entry

        save_index_file(self.base_path, self.hunting_index)

    def create_docs_folder(self, file_path: Path) -> Path:
        """Create the docs folder if it doesn't exist and return the path."""
        docs_folder = file_path.parent.parent / "docs"
        docs_folder.mkdir(parents=True, exist_ok=True)
        return docs_folder

    def generate_integration_links(self, integrations: list[str]) -> list[str]:
        """Generate integration links for the documentation."""
        base_url = "https://docs.elastic.co/integrations"
        generated: list[str] = []
        for integration in integrations:
            if integration in STATIC_INTEGRATION_LINK_MAP:
                link_str = STATIC_INTEGRATION_LINK_MAP[integration]
            else:
                link_str = integration.replace(".", "/")
            link = f"{base_url}/{link_str}"
            validate_link(link)
            generated.append(f"[{integration}]({link})")
        return generated

    def update_index_md(self) -> None:
        """Update the index.md file based on the entries in index.yml."""
        index_file = self.base_path / "index.yml"
        index_content = "# List of Available Queries\n\nHere are the queries currently available:\n"

        if not index_file.exists():
            click.echo(f"No index.yml found at {index_file}. Skipping index.md update.")
            return

        for folder, files in sorted(self.hunting_index.items()):
            index_content += f"\n\n## {folder}\n"
            for file_info in sorted(files.values(), key=lambda x: x["name"]):
                md_path = file_info["path"].replace("queries", "docs").replace(".toml", ".md")
                index_content += f"- [{file_info['name']}]({md_path}) (ES|QL)\n"

        index_md_path = self.base_path / "index.md"
        _ = index_md_path.write_text(index_content, encoding="utf-8")
        click.echo(f"Index Markdown updated at: {index_md_path}")
