# Auto-generate Exception List IDs on Import

When using `import-rules` to load rule TOML files that have `id` fields stripped
from their `exceptions_list` blocks, Kibana rejected the request with an error
similar to:

```
(unknown id): (400) exceptions_list.0.id: Required
```

The import workflow now assigns a random UUID to each exception list entry that
lacks an `id` before sending the payload to Kibana. This ensures rules without
IDs can be imported successfully while keeping exported files clean when using
`--strip-exception-list-id`.
