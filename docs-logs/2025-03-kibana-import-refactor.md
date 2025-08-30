# Kibana import-rules refactor

## Summary
Refactored the `kibana import-rules` command to a modular architecture and
updated related helpers.  The new flow imports value lists, exception lists,
timeline templates and rules in clearly separated phases and prints
human-readable log messages (`name - id - message`).  `RuleResource.import_rules`
now returns `RuleResource` objects for successful imports to simplify
consumers.

## Implementation Notes
- Updated `lib/kibana/kibana/resources.py` to change the return signature of
  `RuleResource.import_rules`.
- Rewrote `detection_rules/kbwrap.py` with a five phase import pipeline and
  detailed comments for each step.
- Added `_suggest_reimport` helper to keep previous guidance for transient
  Kibana API errors.
- Adjusted logging to show both resource names and identifiers.

## Files
- `detection_rules/kbwrap.py`
- `lib/kibana/kibana/resources.py`

# Kibana Rule Import Refactor

## 1. Previous Situation and Issues
The former `kibana import-rules` implementation was a single monolithic
function.  It interleaved collection of rule dependencies with the actual
API calls which made the execution flow hard to follow.  Logging identified
objects only by ID which was confusing when working with real data.  The
function also opened and closed the Kibana client multiple times and mixed
file parsing with network operations.

## 2. Desired State
A modular import workflow with clearly separated phases was required.  Each
phase should deal with one resource type (rules, exception lists, value
lists, timeline templates, action connectors).  Dependencies between phases
must be explicit so that, for example, value lists are only imported when
referenced by exception lists that themselves are needed by imported rules.
Output should use the more human friendly format `name - id - message`.

## 3. New Architecture and Flow
The refactored command in `kbwrap.py` follows five phases:

1. **Preparation** – parse rule TOML files and discover referenced resources.
2. **Exception lists** – check existence, honour overwrite flags and record
   required value lists.
3. **Value lists** – create/update lists that are actually referenced by the
   selected exceptions.
4. **Timeline templates** – import templates so rules can reference them.
5. **Rule import** – send rules, exceptions and action connectors in one API
   request.

All phases run inside a single Kibana client context ensuring that helper
functions in `resources.py` can access the active connection.  Logging now
prints `name - id` for every item and appends an error message when
available.  The `RuleResource.import_rules` helper in `resources.py` was
updated to return full rule resources for successful imports which simplifies
logging of rule names.

## 4. Testing
In summary:

- Import into a fresh space succeeded and imported rules, exception lists,
  value lists and timeline templates.
- Re-running without overwrite flags reported existing resources and skipped
  import.
- Re-running with overwrite flags updated all resources.
- Importing with `--exclude-exceptions "Test02 - Windows Event Log Modified"`
  skipped the corresponding exception list and its value list.

