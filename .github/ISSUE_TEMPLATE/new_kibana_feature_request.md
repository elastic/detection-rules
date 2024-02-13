---
name: Kibana schema update feature request
about: 'New Kibana schema feature request.'
title: "[FR] Update schemas to support <name of new feature>"
labels: "Area: DED,Team: TRADE,schema,python,enhancement"
assignees: ''
projects: "elastic/1268,elastic/1271"

---

## Summary
<!-- A clear and concise statement summarizing the goal and success criteria of the new feature If there is a parent link it here. -->



## Tasks
<!-- Outline the Meta tasks that fall under this Epic, each with a brief description. These should guide the creation of separate Meta issues. METAs should be detailed enough to capture key deliverables. -->

```[tasklist]
#### PR Checklist
- [ ] Link to the relevant Kibana PR or issue provided
- [ ] Exported detection rule(s) from Kibana to showcase the feature(s)
- [ ] Converted the exported ndjson file(s) to toml in the detection-rules repo
- [ ] Re-exported the toml rule(s) to ndjson and re-imported into Kibana
- [ ] Updated necessary unit tests to accommodate the feature
- [ ] Applied min_compat restrictions to limit the feature to a specified minimum stack version
- [ ] Executed all unit tests locally with a test toml rule to confirm passing
- [ ] Included Kibana PR implementer as an optional reviewer for insights on the feature
- [ ] Implemented requisite downgrade functionality
- [ ] Cross-referenced the feature with product documentation for consistency
- [ ] Incorporated a comprehensive test rule in unit tests for full schema coverage
- [ ] Conducted system testing, including fleet, import, and create APIs
```

## Dependencies and Constraints
<!-- Identify any dependencies that could impact the progress of this issue, including external resources, team availability, or technology constraints. Detail the resources needed to complete the task, such as access to specific platforms, tools, or expertise. For example, we may not want to merge this feature until the produce is ga.-->
...
