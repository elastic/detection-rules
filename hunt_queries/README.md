# Hunt Queries

Welcome to the `hunt_queries` folder within the `detection-rules` repository! This folder contains a curated collection of threat hunting queries designed to enhance security monitoring and threat detection capabilities using the Elastic Stack. Each file in this directory provides a query tailored for identifying specific security threats or suspicious activities.

These queries are designed for use with the Elastic Security platform, part of the broader Elastic Stack, enabling security teams to proactively hunt for potential threats in their environment.

## How to Contribute

Contributing to the `hunt_queries` folder is a great way to share your expertise and enhance the security community's capabilities. Here are the guidelines for contributing:

- **Adding New Queries**: Ensure that any new queries are named descriptively and grouped by the type of threat they address. Query files should be named in a way that reflects the nature of the threat or behavior they are designed to detect. Content should include:
  - The query itself
  - A description of the query
  - A description of the security relevance
  - Metadata (author, license, creation date, updated date)
- **Field Usage**: Use standardized fields where possible to ensure that queries are compatible across different data environments and sources.
- **Documentation**: Update the README.md with a brief description of the new query, including its purpose and how it functions. Be sure to add a reference to the new rule in the list of available queries.
- **Review and Pull Requests**: Follow the standard [contributing guide](../CONTRIBUTING.md).

## List of Available Queries

Here are some of the queries currently available in this folder:

- [Sensitive Content Refusal Detection](./llm_sensitive_content_refusal_detection.md): Detects when an LLM refuses to provide information on sensitive topics multiple times.
- [Denial of Service or Resource Exhaustion Attacks Detection](./llm_dos_resource_exhaustion_detection.md): Identifies high-volume token usage that might indicate DoS attacks or resource exhaustion.
- [Monitoring for Latency Anomalies](./llm_latency_anomalies_detection.md): Tracks significant latency differences to identify potential performance issues or security threats.

