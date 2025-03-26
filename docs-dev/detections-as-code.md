# Detection as Code (DaC) Components in Detection-Rules Repo

The **detection-rules** repository contains features for **Detections as Code (DaC)**. These components, including CLI options and workflows, provide methods to help apply DaC principles in practice. The specific DaC architecture should be carefully considered before implementation, for more conceptual ideas and details about DaC, refer to the [DaC Documentation](https://dac-reference.readthedocs.io/en/latest/). Reference implementation is shared to facilitate experimentation and community contributions.

> [!NOTE]
> This guidance outlines the support scope and best practices for using DaC components within the detection-rules repo. Users should take full responsibility for their usage of this repo, thoroughly test these tools in their environments, and verify functionality before using them.

---

## Support and Scope

Supported DaC components that interact with the Elastic Security Solution:
- kibana export-rules ([link](https://github.com/elastic/detection-rules/blob/main/CLI.md#exporting-rules))
- kibana import-rules ([link](https://github.com/elastic/detection-rules/blob/main/CLI.md#using-import-rules))
- import-rules-to-repo ([link](https://github.com/elastic/detection-rules/blob/main/CLI.md#import-rules-to-repo))
- export-rules-from-repo ([link](https://github.com/elastic/detection-rules/blob/main/CLI.md#uploading-rules-to-kibana))

We welcome general questions, feature requests, and bug reports through the following channels:
- **GitHub Issues**: For raising general questions, bugs, and feature requests related to the detection-rules repo.  
  [GitHub Issues](https://github.com/elastic/detection-rules/issues)
- **Community Slack**: For informal discussions or questions (note that message history is limited to 30 days).  
  [Elastic Security Community Slack](https://elasticstack.slack.com/archives/C06TE19EP09)

Support tickets related to this DaC reference implementation can be opened with Elastic, however since the logic is just a wrapper of the underlying product API's, we ask to resolve urgent DaC issues via direct interaction with the underlying [Kibana APIs](https://www.elastic.co/docs/api/doc/kibana/v8/group/endpoint-security-detections-api) or [Elastic Security Solution UI](https://www.elastic.co/guide/en/security/current/rules-ui-management.html), as we will not be able to treat DaC related support requests as a high severity (immediate time frame).

> [!TIP]
> Questions about Kibana API usage should be directed to the Kibana repository:  
> [Kibana Issues](https://github.com/elastic/kibana/issues)

---

## Feature Requests

Feature requests for the DaC components that interact with the Elastic Security Solution (`kibana export-rules`, `kibana import-rules`, `import-rules-to-repo`, and `export-rules-from-repo`) in this repository will be handled similarly to the rest of the detection-rules repo:
- **Prioritization**: Feature requests will be prioritized along with other development work in the repository.
- **Schema Updates**: If there are breaking schema changes in Kibana that affect importing/exporting detection rules, those changes will be prioritized.
- **Rule Engine API**: Current CLI tools leverage the rules engine API, and improvements to this will be treated as part of the ongoing development.
---

## Reference Implementation of DaC Components

DaC is not a single tool. Detection as Code (DaC) is a modern security approach that applies software development best practices to the creation, management, and deployment of security rules. Here is a short summary of several components that extend upon Elastic's rule management capabilities (e.g. query validation, schema validation, unit tests, etc.) provided to help fast track users ability to implement custom DaC implementations in their private environments. If you are new to these concepts, please refer to the [DaC Documentation](https://dac-reference.readthedocs.io/en/latest/), which also provides a quickstart guide and example end-to-end CI/CD workflows.  These components are configurable by using the [custom-rules](custom-rules-management.md) setup.

- Kibana's Rule Versioning Mechanism ([link](https://dac-reference.readthedocs.io/en/latest/internals_of_the_detection_rules_repo.html#option-2-defer-to-elastic-security))
- Local rule management (e.g. autoschema generation, actions and exceptions) ([link](https://dac-reference.readthedocs.io/en/latest/internals_of_the_detection_rules_repo.html#option-1-using-the-built-in-configuration))

---

## Best Practices for Using DaC Components

When implementing DaC in your production environment, follow these best practices:

- **Design and Test Rigorously**: Since every DaC implementation will be user-specific, remember to diligently design, and thoroughly test the tools before deploying them in a production environment.
- **Version Compatibility**: Before upgrading the detection-rules repo version, ensure that you test compatibility with your environment. For more information, see our [Versioning Documentation](https://github.com/elastic/ia-trade-team/issues/471%23issuecomment-2423259800).
- **Limited Backward Compatibility**: We do not guarantee backward compatibility across versions for rule schemas. While we aim to make new fields optional where feasible, there may be minimum version requirements for Elastic Stack and are subject to Kibana's rule schema definitions.
- **Schema Parity**: Not all fields in the schema defined in Kibana are fully supported. Some fields in the detection-rules repo are generalized (e.g., `field = dict()`), while others are more strictly defined. This is due to the complexity of the schemas and the prioritization of Elastic's internal use cases.

