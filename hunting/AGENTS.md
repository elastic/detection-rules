# Agent Instructions: Hunting queries

The `hunting` directory stores threat hunting queries and includes a lightweight CLI located in `hunting/__main__.py`.

- Each hunt consists of a TOML and Markdown file describing the query and context.
- Running `python -m hunting` provides commands to generate markdown, execute queries and manage hunt data.

These utilities are separate from the main `detection_rules` CLI but follow a similar click-based structure.
