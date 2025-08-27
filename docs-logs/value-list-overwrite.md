Bugfix: Overwrite existing value lists without deleting the list.

Importing rules with the `--overwrite-value-lists` flag previously tried to delete
value lists before re-importing their items. Kibana rejects deletion when lists
are referenced by exception items, which left old entries in place and caused
duplicates.

Implementation:
- Added `find_list_items`, `delete_list_item`, and `delete_list_items` helpers to
  `ValueListResource` using the `/api/lists/items/_find` and `/api/lists/items`
  APIs.
- Updated `kibana import-rules` to clear list items when overwriting instead of
  deleting the list container.
- Documented the reasoning in code comments.
