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
See the repository test section for full command output.  In summary:

- Import into a fresh space succeeded and imported rules, exception lists,
  value lists and timeline templates.
- Re-running without overwrite flags reported existing resources and skipped
  import.
- Re-running with overwrite flags updated all resources.
- Importing with `--exclude-exceptions "Test02 - Windows Event Log Modified"`
  skipped the corresponding exception list and its value list.

