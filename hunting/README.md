# Hunt Queries

---

Welcome to the `hunting` folder within the `detection-rules` repository! This directory houses a curated collection of threat hunting queries designed to enhance security monitoring and threat detection capabilities using the Elastic Stack. Each file in this directory provides a query tailored for identifying specific security threats or suspicious activities.

These queries are designed for use with the Elastic Security platform, part of the broader Elastic Stack, enabling security teams to proactively hunt for potential threats in their environment.

- KQL
- EQL
- ES|QL
- OsQuery
- YARA

## How to Contribute

Contributing to the `hunting` folder is a great way to share your expertise and enhance the security community's capabilities. Here’s how you can contribute:

### Names and Related Queries

All query names should be unique and descriptive. If a query's intent is identical or related to another query, consider 
adding a suffix with the integration(s) to the name to indicate the relationship and distinguish them from each other. 
Otherwise, the names do not require the integration, since it is already annotated within the `integration` field.

The filename should reflect the query name.

For example:
- `Detect DLL Hijack via Masquerading as Microsoft Native Libraries - Elastic Defend`
- `Detect DLL Hijack via Masquerading as Microsoft Native Libraries - Sysmon`

### Adding New Queries
- **TOML File Naming and Organization**: Ensure that any new queries are named descriptively and grouped by the type of threat they address. Place your TOML files inside the `queries` folder and ensure they are named in a way that reflects the nature of the threat or behavior they are designed to detect.
- **TOML Fields**: To ensure the hunt queries are consistent and comprehensive, it's important to structure the threat detection rules with specific fields. When contributing a new rule, please include the following fields in the TOML file to describe and configure the analytic:
  - **author**: The name of the individual or organization authoring the rule.
  - **integration**: The specific integration or data source the rule applies to, such as `aws_bedrock.invocation`.
  - **uuid**: A unique identifier for the rule to maintain version control and tracking.
  - **name**: A descriptive name for the rule that clearly indicates its purpose.
  - **language**: The query language used in the rule, such as `KQL`, `EQL`, `ES|QL`, `OsQuery`, or `YARA`.
  - **query**: The actual query or analytic expression written in the appropriate query language that executes the detection logic.
  - **notes**: An array of strings providing detailed insights into the rationale behind the rule, suggestions for further investigation, and tips on distinguishing false positives from true activity.
  - **mitre**: Reference to applicable MITRE ATT&CK tactics or techniques that the rule addresses, enhancing the contextual understanding of its security implications.
  - **references**: Links to external documents, research papers, or websites that provide additional information or validation for the detection logic.

- **Documentation (Optional)**: Include a `README.md` in each subfolder describing the queries and their purposes. This would include a brief description of the new category.

### Field Usage
Use standardized fields where possible to ensure that queries are compatible across different data environments and sources.

### Review and Pull Requests
Follow the standard [contributing guide](../CONTRIBUTING.md). Please remember to use the generate_markdown.py script to update the documentation after adding or updateing queries.

## Using the Script to Generate Markdown

The `generate_markdown.py` script is provided to automate the creation of Markdown files from TOML rule definitions. Here’s how to use it:

- **Generating Markdown**: Run `python generate_markdown.py` from the root of the `hunting` directory. This will generate Markdown files for each TOML file and update the `index.md` to include links to the new Markdown files.
- **Structure**: Rules should be written in TOML and saved under the respective `hunt/*/rules/` directory. The script will automatically convert them into Markdown and save them in the `docs` directory within the respective category folder.

### Sample Directory Structure Example

```config
.
├── README.md
├── generate_markdown.py
├── index.md
└── categorical_folder_name
    ├── README.md
    ├── docs
    │   └── generated_markdown.md
    └── rules
        └── hunt_query.toml
```
