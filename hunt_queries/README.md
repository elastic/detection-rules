# Hunt Queries

---

Welcome to the `hunt_queries` folder within the `detection-rules` repository! This directory houses a curated collection of threat hunting queries designed to enhance security monitoring and threat detection capabilities using the Elastic Stack. Each file in this directory provides a query tailored for identifying specific security threats or suspicious activities.

These queries are designed for use with the Elastic Security platform, part of the broader Elastic Stack, enabling security teams to proactively hunt for potential threats in their environment.

## How to Contribute

Contributing to the `hunt_queries` folder is a great way to share your expertise and enhance the security community's capabilities. Here’s how you can contribute:

### Adding New Queries
- **Naming and Organization**: Ensure that any new queries are named descriptively and grouped by the type of threat they address. Place your TOML files inside the `rules` folder and ensure they are named in a way that reflects the nature of the threat or behavior they are designed to detect.
- **Description Section**: Include as much detail as possible in the description section of the query. This should include information on what the query does, why it is important, and how it can be used to detect threats. This may include references, example evidence, related MITRE techniques, and other relevant information.
- **Documentation (Optional)**: Include a `README.md` in each subfolder describing the queries and their purposes. This would include a brief description of the new category.

### Field Usage
- Use standardized fields where possible to ensure that queries are compatible across different data environments and sources.

### Review and Pull Requests
- Follow the standard [contributing guide](../CONTRIBUTING.md).

## Using the Script to Generate Markdown

The `generate_markdown.py` script is provided to automate the creation of Markdown files from TOML rule definitions. Here’s how to use it:

- **Generating Markdown**: Run `python generate_markdown.py` from the root of the `hunt_queries` directory. This will generate Markdown files for each TOML file and update the `index.md` to include links to the new Markdown files.
- **Structure**: Rules should be written in TOML and saved under the `rules` directory. The script will automatically convert them into Markdown and save them in the `docs` directory within the respective category folder.

### Directory Structure Example

```config
.
├── README.md
├── generate_markdown.py
├── index.md
└── folder_name
    ├── README.md
    ├── docs
    │   └── generated_markdown.md
    └── rules
        └── hunt_query.toml
```
