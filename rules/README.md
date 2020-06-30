# rules/

Rules within this folder are organized by solution or platform. The structure is flattened out, because nested file hierarchies are hard to navigate and find what you're looking for. Each directory contains several [.toml](https://github.com/toml-lang/toml) files, and the primary ATT&CK tactic is included in the file name when it's relevant (i.e. [`windows/execution_via_compiled_html_file.toml`](windows/execution_via_compiled_html_file.toml))  

| folder                              |  description                                                         |
|-------------------------------------|----------------------------------------------------------------------|
| `.`                                 | Root directory where rules are stored                                |
| [`apm/`](apm)                       | Rules that use Application Performance Monitoring (APM) data sources |
| [`aws/`](aws)                       | Rules written for the Amazon Web Services (AWS) module of filebeat   |
| [`cross-platform/`](cross-platform) | Rules that apply to multiple platforms, such as Windows and Linux    |
| [`endpoint/`](endpoint)             | Rules specifically for Elastic Endpoint Security solution            |
| [`linux/`](linux)                   | Rules for Linux or other Unix based operating systems                |
| [`macos/`](macos)                   | Rules for macOS                                                      |
| [`ml/`](ml)                         | Rules that use machine learning jobs (ML)                            |
| [`network/`](network)               | Rules that use network data sources                                  |
| [`okta/`](okta)                     | Rules written for the Okta module of filebeat                        |
| [`windows/`](windows)               | Rules for the Microsoft Windows Operating System                     |
