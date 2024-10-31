# Hunt Queries 🎯

---

Welcome to the `hunting` folder within the `detection-rules` repository! This directory houses a curated collection of threat hunting queries designed to enhance security monitoring and threat detection capabilities using the Elastic Stack. Each file in this directory provides a query tailored for the initial evidence gathering of specific hunts.

Each hunt has a designated TOML and Markdown file, intended to be used either programatically or via copy and pasted. Notes about data considerations, pivoting, exploring data further and more have been added to each hunting query. These queries are designed for use with the Elastic Security platform, part of the broader Elastic Stack, enabling security teams to proactively hunt for potential threats in their environment.

Note that some hunting files will include a mix of queries with different languages whose sole purpose is to provide optional queries to gather evidence for the hunt.

- [KQL](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)
- [EQL](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html)
- [ES|QL](https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html)
- [OsQuery/SQL](https://www.elastic.co/guide/en/kibana/current/osquery.html)
- [YARA](https://yara.readthedocs.io/en/stable/writingrules.html)

The hunting queries shared in this folder are a mix of the following hunting methods:

- Hypothesis-Driven - Assumed breach method with specific hypothesis of where adversary dwells or where footprints exist.
- CTI-Driven - Retro-active searches for specific indicators-of-compromise or tactics, techniques and procedures (TTPs) related to adversaries and/or tooling.
- Data-Driven - Initial evidence collecting query that requires more advanced data analysis to uncover anomalies.

## How to Contribute

Contributing to the `hunting` folder is a great way to share your expertise and enhance the security community's capabilities. Here’s how you can contribute:

### Names and Related Queries

All query names should be unique and descriptive. If a query's intent is identical or related to another query, consider
adding a suffix with the integration(s) to the name to indicate the relationship and distinguish them from each other.
Otherwise, the names do not require the integration, since it is already annotated within the `integration` field.

### Adding New Queries
- **TOML File Naming and Organization**: Ensure that any new queries are named descriptively and grouped by the type of threat they address. Place your TOML files inside the `queries` folder and ensure they are named in a way that reflects the nature of the threat or behavior they are designed to detect.
- **TOML Fields**: To ensure the hunt queries are consistent and comprehensive, it's important to structure the threat detection rules with specific fields. When contributing a new rule, please include the following fields in the TOML file to describe and configure the analytic:
  - **author**: The name of the individual or organization authoring the rule.
  - **description**: The purpose of the hunt with a clear threat explanation and hunting goal.
  - **integration**: The specific integration or data source the rule applies to, such as `aws_bedrock.invocation`.
  - **uuid**: A unique identifier for the rule to maintain version control and tracking.
  - **name**: A descriptive name for the rule that clearly indicates its purpose.
  - **language**: The query language(s) used in the rule, such as `KQL`, `EQL`, `ES|QL`, `SQL`, or `YARA`. Please note, `SQL` may be used in TOML hunting files, but refers to OSQuery.
  - **query**: An array of actual queries or analytic expressions written in the appropriate query language that executes the detection logic.
  - **notes**: An array of strings providing detailed insights into the rationale behind the rule, suggestions for further investigation, and tips on distinguishing false positives from true activity.
  - **mitre**: Reference to applicable MITRE ATT&CK tactics or techniques that the rule addresses, enhancing the contextual understanding of its security implications.
  - **references**: Links to external documents, research papers, or websites that provide additional information or validation for the detection logic.

#### Query Best Practices
* Use `KEEP` command to select specific fields that are relevant or necessary for `STATS` command
* Use `LIMIT` command to limit the number of results, depending on expected result volume
* Filter as much as possible in `WHERE` command to reduce events needed to be processed
* For `FROM` command for index patterns, be as specific as possible to reduce potential event matches that are irrelevant
* Use `STATS` to aggregate results into a tabular format for optimization

### Field Usage
Use standardized fields where possible to ensure that queries are compatible across different data environments and sources.

### Review and Pull Requests
Follow the standard [contributing guide](../CONTRIBUTING.md). Please remember to use the `generate-markdown` command to update the documentation after adding or updating queries.

## Commands

The `hunting` folder is an executable package with its own CLI using [click](https://pypi.org/project/click/). All commands can be ran from the root of `detection-rules` repository as such: `python -m hunting COMMAND`.

- **generate-markdown**:
  - This will generate Markdown files for each TOML file specified and update the `index.yml` and `index.md`.
  - The `path` parameter is to enable users to specify a single file path of the TOML file, an existing folder (i.e. `aws`) or none, which will generate markdown docs for all hunt queries.
  - Rules should be written in TOML and saved under the respective `hunt/*/rules/` directory before running this command. The command will automatically convert them into Markdown and save them in the `docs` directory within the respective category folder.
- **refresh-index**:
  - This will load all hunting query TOML files, then overwrite the existing `index.yml`, followed by updating the `index.md` file
  - This is important whenever new hunts are created or name, file path or MITRE changes are introduced to existing queries.
  - The `search` command relies on the `index.yml` file, so keeping this up-to-date is crucial.
- **search**:
  - This command enables users to filter for queries based on MITRE ATT&CK information, more specifically, tactic, technique or sub-technique IDs. The `--tactic`, `--technique`, `--subtechnique` parameters can be used to search for hunting queries that have been tagged with these respective IDs.
  - All hunting queries are required to include MITRE mappings. Additionally, `--data-source` parameter can be used with or without MITRE filters to scope to a specific data source (i.e. `python -m hunting search --tactic TA0001 --data-source aws` would show all credential access related hunting queries for AWS)
  - More open-ended keyword searches are available via `--keyword` search that can be paired with data source or not to search across a hunting content's name, description, notes and references data.
- **run-query**: **NOTE** - This command requires the `.detection-rules-cfg.yaml` to be populated. Please refer to the [CLI docs](../CLI.md) for optional parameters.
  - This command enables users to load a TOML file, select a hunting query and run it against their elasticsearch instance The `--uuid` and `--file-path` parameters can be used to select which hunting query(s) to run.
  - Users can select which query to run from the TOML file if multiple are available.
  - This command is only meant to identify quickly if matches of the hunting query are found or not. It is recommended to pivot into the UI to either extend the range of the query or investigate matches.
  - Only `ES|QL` queries are compatible with this command, but will be determined programmatically by this command if any are available.
- **view-hunt**:
  - This command outputs the contents of a hunting file in either JSON or TOML. The `--uuid` and `--file-path` parameters enable users to view by UUID or file path.
  - The `--query-only` parameter will only output the queries within the TOML file.
- **hunt-summary**:
  - This command outputs a summary of all hunting queries in the repository. The `--breakdown` parameter enables users to see the summary based on integration, language, or platform.

## Add a Hunt Workflow

To contribute to the `hunting` folder or add new hunting queries, follow these steps:

1. **Clone (or fork) and Install Dependencies**
   - `git clone git@github.com:elastic/detection-rules.git` to clone the repository
   - Setup your own virtual environment if not already established
   - `pip install ".[hunting]"`

2. **Create a TOML File**
   - Navigate to the respective folder (e.g., `aws/queries`, `macos/queries`) and create a new TOML file for your query.
   - Ensure that the file is named descriptively, reflecting the purpose of the hunt (e.g., `credential_access_detection.toml`).

3. **Add Relevant and Required Hunting Information**
   - Fill out the necessary fields in your TOML file. Be sure to include information such as the author, description, query language, actual queries, MITRE technique mappings, and any notes or references. This ensures the hunt query is complete and provides valuable context for threat hunters.

4. **Generate the Markdown File**
   - Once the TOML file is ready, use the following command to generate the corresponding Markdown file:
     ```bash
     python -m hunting generate-markdown
     ```
   - This will create a Markdown file in the `docs` folder under the respective integration, which can be used for documentation or sharing.

5. **Refresh the Indexes**
   - After generating the Markdown, run the `refresh-indexes` command to update the `index.yml` and `index.md` files:
     ```bash
     python -m hunting refresh-index
     ```
   - This ensures that the new hunt query is reflected in the overall index and is available for searching.

6. **Open a Pull Request (PR) for Contributions**
   - If you're contributing the query to the project, submit a Pull Request (PR) with your changes. Be sure to include a description of your query and any relevant details to facilitate the review process.

By following this workflow, you can ensure that your hunt queries are properly formatted, documented, and integrated into the Elastic hunting library.


### Sample Directory Structure Example

```config
.
├── __init__.py
├── __main__.py
├── definitions.py
├── index.md
├── index.yml
├── markdown.py
├── README.md
├── run.py
├── search.py
├── utils.py
└── categorical_folder_name
    ├── docs
    │   └── generated_markdown.md
    └── rules
        └── hunt_query.toml
```
