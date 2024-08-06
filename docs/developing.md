# Developing

Notes for managing and internal development

## Transforms

Transforms are data structures within rules which will be integrated into other fields at build
time for rules, meaning they are not directly converted.

### CLI

There are some helper commands to assist with converting transforms into the excpected rule TOML format

- create transform in Kibana
- export it (or copy it)
- run the following commmand and paste them (multiple)
- copy and paste into rule, with minor format changes if needed

```console
(detection_dev) ➜  detection-rules git:(initial_inv_queries) python -m detection_rules dev transforms guide-plugin-convert

█▀▀▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄   ▄      █▀▀▄ ▄  ▄ ▄   ▄▄▄ ▄▄▄
█  █ █▄▄  █  █▄▄ █    █   █  █ █ █▀▄ █      █▄▄▀ █  █ █   █▄▄ █▄▄
█▄▄▀ █▄▄  █  █▄▄ █▄▄  █  ▄█▄ █▄█ █ ▀▄█      █ ▀▄ █▄▄█ █▄▄ █▄▄ ▄▄█

Enter plugin contents []: !{investigate{"label":"Alerts associated with the host in the last 48h","providers":[[{"field":"event.kind","excluded":false,"queryType":"phrase","value":"signal","valueType":"string"},{"field":"host.name","excluded":false,"queryType":"phrase","value":"{{host.name}}","valueType":"string"}]],"relativeFrom":"now-48h/h","relativeTo":"now"}}
[transform]

[[transform.investigate]]
label = "Alerts associated with the host in the last 48h"
providers = [[{field = "event.kind", excluded = false, queryType = "phrase", value = "signal", valueType = "string"}, {field = "host.name", excluded = false, queryType = "phrase", value = "{{host.name}}", valueType = "string"}]]
relativeFrom = "now-48h/h"
relativeTo = "now"
```

Other transform support can be found under

`python -m detection-rules dev transforms -h`

#### Testing bypasses with environment variables

Using the environment variable `DR_BYPASS_NOTE_VALIDATION_AND_PARSE` will bypass the Detection Rules validation on the `note` field in toml files.

Using the environment variable `DR_BYPASS_BBR_LOOKBACK_VALIDATION` will bypass the Detection Rules lookback and interval validation
on the building block rules.

Using the environment variable `DR_BYPASS_TAGS_VALIDATION` will bypass the Detection Rules Unit Tests on the `tags` field in toml files.

Using the environment variable `DR_BYPASS_TIMELINE_TEMPLATE_VALIDATION` will bypass the timeline template id and title validation for rules. 


## Using the `RuleResource` methods built on detections `_bulk_action` APIs

The following is meant to serve as a simple example of to use the methods

```python
import kibana
from kibana import definitions

rids = ['40e1f208-aaaa-bbbb-98ea-378ccf504ad3', '5e9bc07c-cccc-dddd-a6c0-1cae4a0d256e']

# with TypedDict, either is valid, both with static type checking
set_tags = definitions.RuleBulkSetTags(type='set_tags', value=['tag1', 'tag2'])
delete_tags: definitions.RuleBulkDeleteTags = {'type': 'delete_tags', 'value': ['tag1', 'tag2']}

with kibana:
    r1 = RuleResource.bulk_enable(rids, dry_run=True)
    r2 = RuleResource.bulk_disable(rids, dry_run=True)
    r3 = RuleResource.bulk_duplicate(rids, dry_run=True)
    r4 = RuleResource.bulk_export(rids)
    r5 = RuleResource.bulk_edit(edit_object=[set_tags, delete_tags], rule_ids=rids, dry_run=True)
    r6 = RuleResource.bulk_delete(rids, dry_run=True)
```
