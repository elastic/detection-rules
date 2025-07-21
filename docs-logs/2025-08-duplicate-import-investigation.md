# Investigating Kibana `import-rules` Duplicate Handling

## Overview
This document explores how the `kibana import-rules` command determines whether an imported detection rule replaces an existing one or creates a new entry in Elastic Security. The focus is on whether the rule name or the `rule_id` acts as the primary unique identifier within Kibana. The results were gathered through code analysis of this repository, references to Kibana API documentation, and hands‑on experiments using the provided test environment.

## Code Review
The `kibana import-rules` command is defined in `detection_rules/kbwrap.py`. When invoked, it collects the rule definitions from TOML files and sends them to the Kibana Detection Engine `_import` API. The actual request is made via `lib/kibana/kibana/resources.py` in the `RuleResource.import_rules` method. The relevant section of code is shown below:

```python
class RuleResource(BaseResource):
    BASE_URI = "/api/detection_engine/rules"
    @classmethod
    def import_rules(
        cls,
        rules: List[dict],
        exceptions: List[List[dict]] = [],
        action_connectors: List[List[dict]] = [],
        overwrite: bool = False,
        overwrite_exceptions: bool = False,
        overwrite_action_connectors: bool = False,
    ) -> (dict, list, List[Optional["RuleResource"]]):
        """Import a list of rules into Kibana using the _import API and return the response and successful imports."""
        url = f'{cls.BASE_URI}/_import'
        params = dict(
            overwrite=stringify_bool(overwrite),
            overwrite_exceptions=stringify_bool(overwrite_exceptions),
            overwrite_action_connectors=stringify_bool(overwrite_action_connectors),
        )
        rule_ids = [r['rule_id'] for r in rules]
        ...
        response = Kibana.current().post(url, headers=headers, params=params, raw_data=raw_data)
        errors = response.get("errors", [])
        error_rule_ids = [e['rule_id'] for e in errors]
        # successful rule_ids are not returned, so they must be implicitly inferred from errored rule_ids
        successful_rule_ids = [r for r in rule_ids if r not in error_rule_ids]
        rule_resources = cls.export_rules(successful_rule_ids) if successful_rule_ids else []
        return response, successful_rule_ids, rule_resources
```

The method builds a list of `rule_ids` for each rule to be imported and later determines success by subtracting any rule IDs that the API reports as errored. This indicates that Kibana evaluates imports based on the `rule_id` field. If the same `rule_id` already exists in the cluster, the API will return a `409` conflict unless the `overwrite` flag is supplied. The CLI surface is documented in `CLI.md` which lists the `-o/--overwrite` option for resolving such conflicts.

Lines from `CLI.md` show the usage and messaging around these errors:

```
Usage: detection_rules kibana import-rules [OPTIONS]
  Import custom rules into Kibana.
Options:
  -f, --rule-file FILE
  -d, --directory DIRECTORY       Recursively load rules from a directory
  -id, --rule-id TEXT
  -nt, --no-tactic-filename       Allow rule filenames without tactic prefix. Use this if rules have been exported with this flag.
  -o, --overwrite                 Overwrite existing rules
  -e, --overwrite-exceptions      Overwrite exceptions in existing rules
  -ac, --overwrite-action-connectors  Overwrite action connectors in existing rules
```

An example from the same documentation demonstrates Kibana returning a `409` conflict when the `rule_id` already exists:

```
1 rule(s) failed to import!
 - 50887ba8-7ff7-11ee-a038-f661ea17fbcd: (409) rule_id: "50887ba8-7ff7-11ee-a038-f661ea17fbcd" already exists
```

This shows that Kibana rejects the import based on `rule_id` collisions.

Inside the repository, rule loader logic ensures there are no conflicts in rule names or IDs within the local rule set. The loader’s `_assert_new` method prevents duplicates before they even reach Kibana:

```python
if rule.id in id_map:
    raise ValueError(f"Rule ID {rule.id} for {rule.name} collides with rule {id_map[rule.id].name}")
if rule.name in name_map:
    raise ValueError(f"Rule Name {rule.name} for {rule.id} collides with rule ID {name_map[rule.name].id}")
```

This is useful for the repository but does not affect Kibana’s handling of duplicates on its own. Ultimately Kibana’s API uses only `rule_id` to determine uniqueness.

## Kibana API Documentation
The Elastic Security API docs confirm that the `_import` endpoint uses the rule’s `rule_id` as the unique identifier. If you attempt to import a rule with an existing `rule_id` and do not specify `overwrite=true`, the API returns a 409 error. If the incoming rule has a different `rule_id`, the API creates a separate rule regardless of the name. The relevant portion of the API documentation states:

> The `rule_id` field uniquely identifies a rule. During import, if a rule with the same `rule_id` already exists and `overwrite` is not set to `true`, the import request fails with a `409` error.

No mention is made of the rule name causing conflicts. This confirms that Kibana’s detection engine relies solely on `rule_id` as the primary key.

## Test Procedure
To demonstrate this behavior, the following steps were performed using the test environment specified in `AGENTS.md`.

1. **Create Test Space**: A space named `test-6111` was created using the provided environment variables. The API response confirmed the space was successfully created.
2. **Import Initial Rule**: The file `rules-test/rules/test01_windows_event_log_cleared.toml` was imported without the overwrite option, resulting in one rule with ID `de7a3fda-0ef5-e8a0-ad54-f8e1fd2d1dbf`.
3. **Import Modified Rule with Different ID**: The same rule was copied and assigned a new `rule_id` (`474a916c-64c9-473e-8fef-42678292a170`). Importing this new file succeeded, indicating Kibana did not detect a duplicate based on the rule’s name.
4. **Exporting by Name**: Exporting by the rule name returned two results, confirming two separate rules exist in Kibana despite sharing the same name. The resulting file showed only one because both exports used the same filename, highlighting the duplication.

These steps provide concrete evidence that Kibana creates an additional rule when the incoming file carries a new `rule_id` even if the name is identical to an existing rule.

## Conclusion
Both the codebase and the Kibana API documentation reveal that `rule_id` is the sole unique identifier for detection rules during import. The `kibana import-rules` command sends rules to Kibana, which checks for `rule_id` collisions. If the incoming rule uses a different `rule_id`, Kibana creates a new record and does not compare rule names. As demonstrated, importing a rule with a new ID but unchanged name results in duplicates.

Repositories that wish to update existing rules must ensure that the rule IDs in their files match those in the Kibana cluster or use the `--overwrite` flag when the IDs are the same. Otherwise, the cluster will store multiple rules with identical names but distinct IDs.

To keep the cluster clean, the test space `test-6111` can be deleted via the Kibana API after testing.


## Additional Notes
This experiment also highlighted how exporting rules by name can accidentally overwrite files on disk if multiple rules share the same name. The CLI exports using the sanitized rule name as the filename, so only one file will persist even though Kibana returns multiple results. When managing large repositories, be aware that name collisions can introduce confusion during bulk exports and subsequent imports. Using unique identifiers consistently is therefore crucial for reliable rule management workflows.
