# Skip re-importing existing exception lists

Added a pre-import check to `kibana import-rules` that queries Kibana for any
referenced exception lists. Existing lists are now skipped unless the
`--overwrite-exceptions` flag is provided, preventing deleted items from being
silently recreated. When overwriting is requested, the helper deletes the list
before importing the replacement to ensure an exact match.

## Implementation
- Introduced `ExceptionListResource` with `get` and `delete` helpers for the
  `/api/exception_lists` endpoints.
- Updated `detection_rules/kbwrap.py` to skip or replace lists based on the
  flag and to report skipped lists in the CLI output.
