# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Lightweight builtin toml-markdown converter."""

import tomllib
from pathlib import Path


HUNTING_DIR = Path(__file__).parent


def convert_toml_to_markdown(contents: str, file_path: Path) -> tuple[str, str, str]:
    """Convert TOML content to Markdown format."""
    toml_dict = tomllib.loads(contents)
    hunt = toml_dict['hunt']
    markdown = f"# {hunt['name']}\n\n---\n\n"
    markdown += "## Metadata\n\n"
    markdown += f"- **Data Source:** `{hunt['datasource']}`\n"
    markdown += f"- **Author:** {hunt['author']}\n"
    markdown += f"- **UUID:** `{hunt['uuid']}`\n"
    markdown += f"- **Language:** `{hunt['language']}`\n\n"
    markdown += "## Query\n\n"
    markdown += f"```sql\n{hunt['query']}```\n\n"
    if 'notes' in hunt:
        markdown += "## Notes\n\n"
        for note in hunt['notes']:
            markdown += f"- {note}\n"
    if 'mitre' in hunt:
        markdown += "\n## MITRE ATT&CK Techniques\n\n"
        for technique in hunt['mitre']:
            markdown += f"- [{technique}](https://atlas.mitre.org/techniques/{technique})\n"
    if 'references' in hunt:
        markdown += "\n## References\n\n"
        for reference in hunt['references']:
            markdown += f"- {reference}\n"
        markdown += f"- [{hunt['name']}]({Path('../queries') / file_path.name})\n"
    return markdown, hunt['name'], hunt['language']


def process_toml_files(base_path: Path) -> None:
    """Process all TOML files in the directory recursively and convert them to Markdown."""
    index_content = "# List of Available Queries\n\nHere are the queries currently available:\n\n"
    directories = {}

    for toml_file in base_path.rglob('*.toml'):
        markdown_content, rule_name, language = convert_toml_to_markdown(toml_file.read_text(), toml_file)
        markdown_path = toml_file.parent.parent / 'docs' / f"{toml_file.stem}.md"
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(markdown_content, encoding='utf-8')
        print(f"Markdown generated: {markdown_path}")

        # Prepare the index
        folder_name = toml_file.parent.relative_to(base_path)
        directories.setdefault(folder_name, []).append((markdown_path.name, rule_name, language))

    # Build index content
    for folder, files in sorted(directories.items()):
        index_content += f"## {folder.parent.name}\n"
        for file, name, lang in sorted(files):
            relative_path = folder / 'docs' / file
            index_content += f"- [{name}]({relative_path}) ({lang})\n"

    # Write index file
    base_path.joinpath('index.md').write_text(index_content, encoding='utf-8')
    print(f"Index Markdown generated at: {base_path / 'index.md'}")


if __name__ == "__main__":
    process_toml_files(HUNTING_DIR)
