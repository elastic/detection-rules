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

Other transform suppoprt can be found under

`python -m detection-rules dev transforms -h`
