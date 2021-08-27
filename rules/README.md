# rules/

Rules within this folder are organized by solution or platform. The structure is flattened out, because nested file hierarchies are hard to navigate and find what you're looking for. Each directory contains several [.toml](https://github.com/toml-lang/toml) files, and the primary ATT&CK tactic is included in the file name when it's relevant (i.e. [`windows/execution_via_compiled_html_file.toml`](windows/execution_via_compiled_html_file.toml))

| folder                              |  description                                                         |
|-------------------------------------|----------------------------------------------------------------------|
| `.`                                 | Root directory where rules are stored                                |
| [`apm/`](apm)                       | Rules that use Application Performance Monitoring (APM) data sources |
| [`cross-platform/`](cross-platform) | Rules that apply to multiple platforms, such as Windows and Linux    |
| [`integrations/`](integrations)     | Rules organized by Fleet integration                                 |
| [`linux/`](linux)                   | Rules for Linux or other Unix based operating systems                |
| [`macos/`](macos)                   | Rules for macOS                                                      |
| [`ml/`](ml)                         | Rules that use machine learning jobs (ML)                            |
| [`network/`](network)               | Rules that use network data sources                                  |
| [`promotions/`](promotions)         | Rules that promote external alerts into detection engine alerts      |
| [`windows/`](windows)               | Rules for the Microsoft Windows Operating System                     |


Integration specific rules are stored in the [`integrations/`](integrations) directory:

| folder                                                 |  integration                         |
|--------------------------------------------------------|--------------------------------------|
| [`aws/`](integrations/aws)                             | Amazon Web Services (AWS)            |
| [`azure/`](integrations/azure)                         | Microsoft Azure                      |
| [`cyberarkpas/`](integrations/cyberarkpas)             | Cyber Ark Privileged Access Security |
| [`endpoint/`](integrations/endpoint)                   | Elastic Endpoint Security            |
| [`gcp/`](integrations/gcp)                             | Google Cloud Platform (GCP)          |
| [`google_workspace/`](integrations/google_workspace)   | Google Workspace (formerly GSuite)   |
| [`o365/`](integrations/o365)                           | Microsoft Office                     |
| [`okta/`](integrations/okta)                           | Oka                                  |

