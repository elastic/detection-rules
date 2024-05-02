# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Lightweight builtin toml-markdown converter."""

import tomllib
from pathlib import Path

def convert_toml_to_markdown(toml_content: str):
    """ Convert TOML content to Markdown format. """
    toml_dict = tomllib.loads(toml_content)
    markdown = f"# {toml_dict['hunt']['name']}\n\n---\n\n"
    markdown += "## Metadata\n\n"
    markdown += f"**Author:** {toml_dict['hunt']['author']}\n**UUID:** {toml_dict['hunt']['uuid']}\n\n"
    markdown += "## Query\n\n"
    markdown += f"```sql\n{toml_dict['hunt']['query']}\n```\n\n"
    markdown += "## Description\n\n"
    markdown += f"{toml_dict['hunt']['description']}\n"
    return markdown, toml_dict['hunt']['name']

def process_toml_files(base_path: Path):
    """ Process all TOML files in the directory recursively and convert them to Markdown. """
    index_content = "# List of Available Queries\n\nHere are some of the queries currently available:\n\n"
    directories = {}

    for toml_file in base_path.rglob('*.toml'):
        markdown_content, rule_name = convert_toml_to_markdown(toml_file.read_text())
        markdown_path = toml_file.parent.parent / 'docs' / f"{toml_file.stem}.md"
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(markdown_content, encoding='utf-8')
        print(f"Markdown generated: {markdown_path}")

        # Prepare the index
        folder_name = toml_file.parent.relative_to(base_path)
        directories.setdefault(folder_name, []).append((markdown_path.name, rule_name))

    # Build index content
    for folder, files in directories.items():
        index_content += f"## {folder.parent.name}\n"
        for file, name in files:
            relative_path = folder / 'docs' / file
            index_content += f"- [{name}]({relative_path})\n"

    # Write index file
    (base_path / 'index.md').write_text(index_content, encoding='utf-8')
    print("Index Markdown generated at:", base_path / 'index.md')

if __name__ == "__main__":
    base_dir = Path(__file__).parent
    process_toml_files(base_dir)
