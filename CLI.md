# Command Line Interface (CLI)

This covers more advanced CLI use cases and workflows. To [get started](README.md#getting-started) with the CLI, reference
the [README](README.md). Basic use of the CLI such as [creating a rule](CONTRIBUTING.md#creating-a-rule-with-the-cli) or
[testing](CONTRIBUTING.md#testing-a-rule-with-the-cli) are referenced in the [contribution guide](CONTRIBUTING.md).


## Using a user config file or environment variables

CLI commands which are tied to Kibana and Elasticsearch are capable of parsing auth-related keyword args from a config
file or environment variables.

If a value is set in multiple places, such as config file and environment variable, the order of precedence will be as
follows:
* explicitly passed args (such as `--user joe`)
* environment variables
* config values
* prompt (this only applies to certain values)

#### Setup a user config file

In the root directory of this repo, create the file `.detection-rules-cfg.json` (or `.yaml`) and add relevant values

Currently supported arguments:
* elasticsearch_url
* kibana_url
* cloud_id
* es_user 
* es_password
* api_key

Authenticating to Kibana is only available using api_key.

#### Using environment variables

Environment variables using the argument format: `DR_<UPPERCASED_ARG_NAME>` will be parsed in commands which expect it.
EX: `DR_USER=joe`


Using the environment variable `DR_BYPASS_NOTE_VALIDATION_AND_PARSE` will bypass the Detection Rules validation on the `note` field in toml files.

Using the environment variable `DR_BYPASS_BBR_LOOKBACK_VALIDATION` will bypass the Detection Rules lookback and interval validation
on the building block rules.

Using the environment variable `DR_BYPASS_TAGS_VALIDATION` will bypass the Detection Rules Unit Tests on the `tags` field in toml files.

Using the environment variable `DR_BYPASS_TIMELINE_TEMPLATE_VALIDATION` will bypass the timeline template id and title validation for rules. 

Using the environment variable `DR_CLI_MAX_WIDTH` will set a custom max width for the click CLI. 
For instance, some users may want to increase the default value in cases where help messages are cut off. 

Using the environment variable `DR_REMOTE_ESQL_VALIDATION` will enable remote ESQL validation for rules that use ESQL queries. This validation will be performed whenever the rule is loaded including for example the view-rule command. This requires the appropriate kibana_url or cloud_id, api_key, and es_url to be set in the config file or as environment variables.

Using the environment variable `DR_SKIP_EMPTY_INDEX_CLEANUP` will disable the cleanup of remote testing indexes that are created as part of the remote ESQL validation. By default, these indexes are deleted after the validation is complete, or upon validation error.

## Importing rules into the repo

You can import rules into the repo using the `create-rule` or `import-rules-to-repo` commands. Both of these commands will
require that the rules are schema-compliant and able to pass full validation. The biggest benefit to using these
commands is that they will strip[*](#note) additional fields[**](#note-2) and prompt for missing required
fields.

Alternatively, you can manually place rule files in the directory and run tests to validate as well.

<a id="note">\* Note</a>: This is currently limited to flat fields and may not apply to nested values.<br>
<a id="note-2">\** Note</a>: Additional fields are based on the current schema at the time the command is used.


#### `create-rule`

```console
Usage: detection_rules create-rule [OPTIONS] PATH

  Create a detection rule.

Options:
  -c, --config FILE               Rule or config file
  --required-only                 Only prompt for required fields
  -t, --rule-type [machine_learning|query|threshold]
                                  Type of rule to create
  -h, --help                      Show this message and exit.
```

This command will allow you to pass a rule file using the `-c/--config` parameter. This is limited to one rule at a time
and will accept any valid rule in the following formats:
* toml
* json
* yaml (yup)
* ndjson (as long as it contains only a single rule and has the extension `.ndjson` or `.jsonl`)

#### `import-rules-to-repo`

```console
Usage: detection_rules import-rules-to-repo [OPTIONS] [INPUT_FILE]...

  Import rules from json, toml, or yaml files containing Kibana exported rule(s).

Options:
  -ac, --action-connector-import  Include action connectors in export
  -e, --exceptions-import         Include exceptions in export
  --required-only                 Only prompt for required fields
  -d, --directory DIRECTORY       Load files from a directory
  -s, --save-directory DIRECTORY  Save imported rules to a directory
  -se, --exceptions-directory DIRECTORY
                                  Save imported exceptions to a directory
  -sa, --action-connectors-directory DIRECTORY
                                  Save imported actions to a directory
  -ske, --skip-errors             Skip rule import errors
  -da, --default-author TEXT      Default author for rules missing one
  -snv, --strip-none-values       Strip None values from the rule
  -lc, --local-creation-date      Preserve the local creation date of the rule
  -lu, --local-updated-date       Preserve the local updated date of the rule
  -lr, --load-rule-loading        Enable arbitrary rule loading from the rules directories (Can be very slow!)
  -h, --help                      Show this message and exit.
```

The primary advantage of using this command is the ability to import multiple rules at once. Multiple rule paths can be
specified explicitly with unlimited arguments, recursively within a directory using `-d/--directory`[*](#note-3), or
a combination of both.

In addition to the formats mentioned using `create-rule`, this will also accept an `.ndjson`/`jsonl` file
containing multiple rules (as would be the case with a bulk export).

The `-s/--save-directory` is an optional parameter to specify a non default directory to place imported rules. If it is not specified, the first directory specified in the rules config will be used.

This will also strip additional fields and prompt for missing required fields.

<a id="note-3">\* Note</a>: This will attempt to parse ALL files recursively within a specified directory.

Additionally, the `-e` flag can be used to import exceptions in addition to rules from the export file.


## Commands using Elasticsearch and Kibana clients

Commands which connect to Elasticsearch or Kibana are embedded under the subcommands:
* es
* kibana

These command groups will leverage their respective clients and will automatically use parsed config options if
defined, otherwise arguments should be passed to the sub-command as:

Providers are the name that Elastic Cloud uses to configure authentication in Kibana. When we create deployment, Elastic Cloud configures two providers by default: basic/cloud-basic and saml/cloud-saml (for SSO).

```console
python -m detection_rules kibana -h

█▀▀▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄   ▄      █▀▀▄ ▄  ▄ ▄   ▄▄▄ ▄▄▄
█  █ █▄▄  █  █▄▄ █    █   █  █ █ █▀▄ █      █▄▄▀ █  █ █   █▄▄ █▄▄
█▄▄▀ █▄▄  █  █▄▄ █▄▄  █  ▄█▄ █▄█ █ ▀▄█      █ ▀▄ █▄▄█ █▄▄ █▄▄ ▄▄█

Usage: detection_rules kibana [OPTIONS] COMMAND [ARGS]...

  Commands for integrating with Kibana.

Options:
  --ignore-ssl-errors TEXT
  --space TEXT              Kibana space
  --api-key TEXT
  --cloud-id TEXT           ID of the cloud instance.
  --kibana-url TEXT
  -h, --help                Show this message and exit.

Commands:
  export-rules   Export custom rules from Kibana.
  import-rules   Import custom rules into Kibana.
  search-alerts  Search detection engine alerts with KQL.
  upload-rule    [Deprecated] Upload a list of rule .toml files to Kibana.
```

## Searching Kibana for Alerts

Alerts stored in Kibana can be quickly be identified by searching with the `search-alerts` command.


```console
python -m detection_rules kibana search-alerts -h

█▀▀▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄   ▄      █▀▀▄ ▄  ▄ ▄   ▄▄▄ ▄▄▄
█  █ █▄▄  █  █▄▄ █    █   █  █ █ █▀▄ █      █▄▄▀ █  █ █   █▄▄ █▄▄
█▄▄▀ █▄▄  █  █▄▄ █▄▄  █  ▄█▄ █▄█ █ ▀▄█      █ ▀▄ █▄▄█ █▄▄ █▄▄ ▄▄█

Kibana client:
Options:
  --ignore-ssl-errors TEXT
  --space TEXT              Kibana space
  --api-key TEXT
  --cloud-id TEXT           ID of the cloud instance.
  --kibana-url TEXT

Usage: detection_rules kibana search-alerts [OPTIONS] [QUERY]

  Search detection engine alerts with KQL.

Options:
  -d, --date-range <TEXT TEXT>...
                                  Date range to scope search
  -c, --columns TEXT              Columns to display in table
  -e, --extend                    If columns are specified, extend the original columns
  -m, --max-count INTEGER         The max number of alerts to return
  -h, --help                      Show this message and exit.
```

Running the following command will print out a table showing any alerts that have been generated recently.
`python3 -m detection_rules kibana --provider-name cloud-basic --kibana-url <url> --api-key <api-key> search-alerts`

```console

█▀▀▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄   ▄      █▀▀▄ ▄  ▄ ▄   ▄▄▄ ▄▄▄
█  █ █▄▄  █  █▄▄ █    █   █  █ █ █▀▄ █      █▄▄▀ █  █ █   █▄▄ █▄▄
█▄▄▀ █▄▄  █  █▄▄ █▄▄  █  ▄█▄ █▄█ █ ▀▄█      █ ▀▄ █▄▄█ █▄▄ █▄▄ ▄▄█

===================================================================================================================================
 host                                 rule
 hostname                             name                                                                @timestamp
===================================================================================================================================
 stryker-malwares-MacBook-Pro.local   Sudo Heap-Based Buffer Overflow Attempt                             2022-06-21T14:08:34.288Z
 stryker-malwares-MacBook-Pro.local   Suspicious Automator Workflows Execution                            2022-06-21T13:58:30.857Z
 stryker-malwares-MacBook-Pro.local   Privilege Escalation Enumeration via LinPEAS                        2022-06-21T13:33:18.218Z
 stryker-malwares-MacBook-Pro.local   Privilege Escalation Enumeration via LinPEAS                        2022-06-21T13:28:14.685Z
 stryker-malwares-MacBook-Pro.local   Potential Reverse Shell Activity via Terminal                       2022-06-21T12:53:00.234Z
 stryker-malwares-MacBook-Pro.local   Potential Reverse Shell Activity via Terminal                       2022-06-21T12:53:00.237Z
 stryker-malwares-MacBook-Pro.local   Potential Kerberos Attack via Bifrost                               2022-06-20T20:33:53.810Z
 stryker-malwares-MacBook-Pro.local   Potential Kerberos Attack via Bifrost                               2022-06-20T20:33:53.813Z
 stryker-malwares-MacBook-Pro.local   Potential Privilege Escalation via Root Crontab File Modification   2022-06-20T20:23:50.557Z
 stryker-malwares-MacBook-Pro.local   Download and Execution of JavaScript Payload                        2022-06-20T20:18:46.211Z
===================================================================================================================================

```
## Uploading rules to Kibana

### Using `kibana import-rules`

To directly load Toml formatted rule files into Kibana, one can use the `kibana import-rules` command as shown below.

```
python -m detection_rules kibana import-rules -h

█▀▀▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄   ▄      █▀▀▄ ▄  ▄ ▄   ▄▄▄ ▄▄▄
█  █ █▄▄  █  █▄▄ █    █   █  █ █ █▀▄ █      █▄▄▀ █  █ █   █▄▄ █▄▄
█▄▄▀ █▄▄  █  █▄▄ █▄▄  █  ▄█▄ █▄█ █ ▀▄█      █ ▀▄ █▄▄█ █▄▄ █▄▄ ▄▄█

Kibana client:
Options:
  --ignore-ssl-errors TEXT
  --space TEXT              Kibana space
  --api-key TEXT
  --cloud-id TEXT           ID of the cloud instance.
  --kibana-url TEXT

Usage: detection_rules kibana import-rules [OPTIONS]

  Import custom rules into Kibana.

Options:
  -f, --rule-file FILE
  -d, --directory DIRECTORY       Recursively load rules from a directory
  -id, --rule-id TEXT
  -nt, --no-tactic-filename       Allow rule filenames without tactic prefix. Use this if rules have been exported with this flag.
  -o, --overwrite                 Overwrite existing rules
  -e, --overwrite-exceptions      Overwrite exceptions in existing rules
  -ac, --overwrite-action-connectors
                                  Overwrite action connectors in existing rules
  -h, --help                      Show this message and exit.
```

Example usage of a successful upload:

```
python -m detection_rules kibana import-rules -f test-export-rules/credential_access_NEW_RULE.toml

█▀▀▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄   ▄      █▀▀▄ ▄  ▄ ▄   ▄▄▄ ▄▄▄
█  █ █▄▄  █  █▄▄ █    █   █  █ █ █▀▄ █      █▄▄▀ █  █ █   █▄▄ █▄▄
█▄▄▀ █▄▄  █  █▄▄ █▄▄  █  ▄█▄ █▄█ █ ▀▄█      █ ▀▄ █▄▄█ █▄▄ █▄▄ ▄▄█

1 rule(s) successfully imported
 - 50887ba8-aaaa-bbbb-a038-f661ea17fbcd
```

<details>
<summary>Detailed import-rules output</summary>

Existing rule fails as expected:
```
python -m detection_rules kibana import-rules -f test-export-rules/credential_access_EXISTING_RULE.toml

█▀▀▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄   ▄      █▀▀▄ ▄  ▄ ▄   ▄▄▄ ▄▄▄
█  █ █▄▄  █  █▄▄ █    █   █  █ █ █▀▄ █      █▄▄▀ █  █ █   █▄▄ █▄▄
█▄▄▀ █▄▄  █  █▄▄ █▄▄  █  ▄█▄ █▄█ █ ▀▄█      █ ▀▄ █▄▄█ █▄▄ █▄▄ ▄▄█

1 rule(s) failed to import!
 - 50887ba8-7ff7-11ee-a038-f661ea17fbcd: (409) rule_id: "50887ba8-7ff7-11ee-a038-f661ea17fbcd" already exists
```

`-o` overwrite forces the import successfully
```
python -m detection_rules kibana import-rules -f test-export-rules/credential_access_EXISTING_RULE.toml -o

█▀▀▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄   ▄      █▀▀▄ ▄  ▄ ▄   ▄▄▄ ▄▄▄
█  █ █▄▄  █  █▄▄ █    █   █  █ █ █▀▄ █      █▄▄▀ █  █ █   █▄▄ █▄▄
█▄▄▀ █▄▄  █  █▄▄ █▄▄  █  ▄█▄ █▄█ █ ▀▄█      █ ▀▄ █▄▄█ █▄▄ █▄▄ ▄▄█

1 rule(s) successfully imported
 - 50887ba8-7ff7-11ee-a038-f661ea17fbcd
```

The rule loader detects a collision in name and fails as intended:
```
python -m detection_rules kibana import-rules -d test-export-rules

█▀▀▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄   ▄      █▀▀▄ ▄  ▄ ▄   ▄▄▄ ▄▄▄
█  █ █▄▄  █  █▄▄ █    █   █  █ █ █▀▄ █      █▄▄▀ █  █ █   █▄▄ █▄▄
█▄▄▀ █▄▄  █  █▄▄ █▄▄  █  ▄█▄ █▄█ █ ▀▄█      █ ▀▄ █▄▄█ █▄▄ █▄▄ ▄▄█

Error loading rule in test-export-rules/credential_access_NEW_RULE.toml
Traceback (most recent call last):
  ...snipped stacktrace...
AssertionError: Rule Name Multiple Okta User Auth Events with Same Device Token Hash Behind a Proxy for 50887ba8-aaaa-bbbb-a038-f661ea17fbcd collides with rule ID 50887ba8-7ff7-11ee-a038-f661ea17fbcd
```

Expected failure on rule_id collision:
```
python -m detection_rules kibana import-rules -d test-export-rules

█▀▀▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄   ▄      █▀▀▄ ▄  ▄ ▄   ▄▄▄ ▄▄▄
█  █ █▄▄  █  █▄▄ █    █   █  █ █ █▀▄ █      █▄▄▀ █  █ █   █▄▄ █▄▄
█▄▄▀ █▄▄  █  █▄▄ █▄▄  █  ▄█▄ █▄█ █ ▀▄█      █ ▀▄ █▄▄█ █▄▄ █▄▄ ▄▄█

Error loading rule in test-export-rules/credential_access_multiple_okta_user_auth_events_with_same_device_token_hash_behind_a_proxy.toml
Traceback (most recent call last):
  ...snipped stacktrace...
AssertionError: Rule ID 50887ba8-7ff7-11ee-a038-f661ea17fbcd for Multiple Okta User Auth Events with Same Device Token Hash Behind a Proxy collides with rule Multiple Okta User Auth Events with Same Device Token Hash Behind a Proxy
```

Import a full directory - all fail as expected:
```
python -m detection_rules kibana import-rules -d test-export-rules

█▀▀▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄   ▄      █▀▀▄ ▄  ▄ ▄   ▄▄▄ ▄▄▄
█  █ █▄▄  █  █▄▄ █    █   █  █ █ █▀▄ █      █▄▄▀ █  █ █   █▄▄ █▄▄
█▄▄▀ █▄▄  █  █▄▄ █▄▄  █  ▄█▄ █▄█ █ ▀▄█      █ ▀▄ █▄▄█ █▄▄ █▄▄ ▄▄█

23 rule(s) failed to import!
 - ee663abc-fb77-49d2-a7c5-204b9cf888ca: (409) rule_id: "ee663abc-fb77-49d2-a7c5-204b9cf888ca" already exists
 - 50887ba8-aaaa-bbbb-a038-f661ea17fbcd: (409) rule_id: "50887ba8-aaaa-bbbb-a038-f661ea17fbcd" already exists
 - 50887ba8-7ff7-11ee-a038-f661ea17fbcd: (409) rule_id: "50887ba8-7ff7-11ee-a038-f661ea17fbcd" already exists
 - 8a0fbd26-867f-11ee-947c-f661ea17fbcd: (409) rule_id: "8a0fbd26-867f-11ee-947c-f661ea17fbcd" already exists
 - aaaaaaaa-f861-414c-8602-150d5505b777: (409) rule_id: "aaaaaaaa-f861-414c-8602-150d5505b777" already exists
 - 2f8a1226-5720-437d-9c20-e0029deb6194: (409) rule_id: "2f8a1226-5720-437d-9c20-e0029deb6194" already exists
 - cd66a5af-e34b-4bb0-8931-57d0a043f2ef: (409) rule_id: "cd66a5af-e34b-4bb0-8931-57d0a043f2ef" already exists
 - 2d8043ed-5bda-4caf-801c-c1feb7410504: (409) rule_id: "2d8043ed-5bda-4caf-801c-c1feb7410504" already exists
 - d76b02ef-fc95-4001-9297-01cb7412232f: (409) rule_id: "d76b02ef-fc95-4001-9297-01cb7412232f" already exists
 - cc382a2e-7e52-11ee-9aac-f661ea17fbcd: (409) rule_id: "cc382a2e-7e52-11ee-9aac-f661ea17fbcd" already exists
 - 260486ee-7d98-11ee-9599-f661ea17fbcd: (409) rule_id: "260486ee-7d98-11ee-9599-f661ea17fbcd" already exists
 - ee39a9f7-5a79-4b0a-9815-d36b3cf28d3e: (409) rule_id: "ee39a9f7-5a79-4b0a-9815-d36b3cf28d3e" already exists
 - 1ceb05c4-7d25-11ee-9562-f661ea17fbcd: (409) rule_id: "1ceb05c4-7d25-11ee-9562-f661ea17fbcd" already exists
 - 2e56e1bc-867a-11ee-b13e-f661ea17fbcd: (409) rule_id: "2e56e1bc-867a-11ee-b13e-f661ea17fbcd" already exists
 - 621e92b6-7e54-11ee-bdc0-f661ea17fbcd: (409) rule_id: "621e92b6-7e54-11ee-bdc0-f661ea17fbcd" already exists
 - a198fbbd-9413-45ec-a269-47ae4ccf59ce: (409) rule_id: "a198fbbd-9413-45ec-a269-47ae4ccf59ce" already exists
 - 29b53942-7cd4-11ee-b70e-f661ea17fbcd: (409) rule_id: "29b53942-7cd4-11ee-b70e-f661ea17fbcd" already exists
 - aaec44bc-d691-4874-99b2-48ab7392dfd5: (409) rule_id: "aaec44bc-d691-4874-99b2-48ab7392dfd5" already exists
 - 40e1f208-0f70-47d4-98ea-378ccf504ad3: (409) rule_id: "40e1f208-0f70-47d4-98ea-378ccf504ad3" already exists
 - 5e9bc07c-7e7a-415b-a6c0-1cae4a0d256e: (409) rule_id: "5e9bc07c-7e7a-415b-a6c0-1cae4a0d256e" already exists
 - 17d99572-793d-41ae-8b55-cee30db13fa2: (409) rule_id: "17d99572-793d-41ae-8b55-cee30db13fa2" already exists
 - 38accba8-894a-4f32-98d5-7cb01c82f5d6: (409) rule_id: "38accba8-894a-4f32-98d5-7cb01c82f5d6" already exists
 - e1b7d2a6-d23a-4747-b621-d249d83162ea: (409) rule_id: "e1b7d2a6-d23a-4747-b621-d249d83162ea" already exists
```

Import a full directory, with `-o` forcing the updates successfully
```
python -m detection_rules kibana import-rules -d test-export-rules -o

█▀▀▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄   ▄      █▀▀▄ ▄  ▄ ▄   ▄▄▄ ▄▄▄
█  █ █▄▄  █  █▄▄ █    █   █  █ █ █▀▄ █      █▄▄▀ █  █ █   █▄▄ █▄▄
█▄▄▀ █▄▄  █  █▄▄ █▄▄  █  ▄█▄ █▄█ █ ▀▄█      █ ▀▄ █▄▄█ █▄▄ █▄▄ ▄▄█

23 rule(s) successfully imported
 - ee663abc-fb77-49d2-a7c5-204b9cf888ca
 - 50887ba8-aaaa-bbbb-a038-f661ea17fbcd
 - 50887ba8-7ff7-11ee-a038-f661ea17fbcd
 - 8a0fbd26-867f-11ee-947c-f661ea17fbcd
 - aaaaaaaa-f861-414c-8602-150d5505b777
 - 2f8a1226-5720-437d-9c20-e0029deb6194
 - cd66a5af-e34b-4bb0-8931-57d0a043f2ef
 - 2d8043ed-5bda-4caf-801c-c1feb7410504
 - d76b02ef-fc95-4001-9297-01cb7412232f
 - cc382a2e-7e52-11ee-9aac-f661ea17fbcd
 - 260486ee-7d98-11ee-9599-f661ea17fbcd
 - ee39a9f7-5a79-4b0a-9815-d36b3cf28d3e
 - 1ceb05c4-7d25-11ee-9562-f661ea17fbcd
 - 2e56e1bc-867a-11ee-b13e-f661ea17fbcd
 - 621e92b6-7e54-11ee-bdc0-f661ea17fbcd
 - a198fbbd-9413-45ec-a269-47ae4ccf59ce
 - 29b53942-7cd4-11ee-b70e-f661ea17fbcd
 - aaec44bc-d691-4874-99b2-48ab7392dfd5
 - 40e1f208-0f70-47d4-98ea-378ccf504ad3
 - 5e9bc07c-7e7a-415b-a6c0-1cae4a0d256e
 - 17d99572-793d-41ae-8b55-cee30db13fa2
 - 38accba8-894a-4f32-98d5-7cb01c82f5d6
 - e1b7d2a6-d23a-4747-b621-d249d83162ea

```

</details>

### Using `export-rules-from-repo`

Toml formatted rule files can also be imported into Kibana through Kibana security app via a consolidated ndjson file
which is exported from detection rules.

```console
Usage: detection_rules export-rules-from-repo [OPTIONS]

  Export rule(s) and exception(s) into an importable ndjson file.

Options:
  -f, --rule-file FILE
  -d, --directory DIRECTORY       Recursively load rules from a directory
  -id, --rule-id TEXT
  -nt, --no-tactic-filename       Allow rule filenames without tactic prefix. Use this if rules have been exported with this flag.
  -o, --outfile PATH              Name of file for exported rules
  -r, --replace-id                Replace rule IDs with new IDs before export
  --stack-version [7.8|7.9|7.10|7.11|7.12|7.13|7.14|7.15|7.16|8.0|8.1|8.2|8.3|8.4|8.5|8.6|8.7|8.8|8.9|8.10|8.11|8.12|8.13|8.14|8.15|8.16|8.17|8.18|9.0]
                                  Downgrade a rule version to be compatible with older instances of Kibana
  -s, --skip-unsupported          If `--stack-version` is passed, skip rule types which are unsupported (an error will be raised otherwise)
  --include-metadata              Add metadata to the exported rules
  -ac, --include-action-connectors
                                  Include Action Connectors in export
  -e, --include-exceptions        Include Exceptions Lists in export
  -h, --help                      Show this message and exit.
```

_*To load a custom rule, the proper index must be setup first. The simplest way to do this is to click
the `Load prebuilt detection rules and timeline templates` button on the `detections` page in the Kibana security app._


### Deprecated Methods

Toml formatted rule files can also be uploaded as custom rules using the `kibana upload-rule` command. This command is 
deprecated as of Elastic Stack version 9.0, but is included for compatibility with older stacks. To upload more than one
file, specify multiple files at a time as individual args. This command is meant to support uploading and testing of
rules and is not intended for production use in its current state.

```console
python -m detection_rules kibana upload-rule -h

█▀▀▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄   ▄      █▀▀▄ ▄  ▄ ▄   ▄▄▄ ▄▄▄
█  █ █▄▄  █  █▄▄ █    █   █  █ █ █▀▄ █      █▄▄▀ █  █ █   █▄▄ █▄▄
█▄▄▀ █▄▄  █  █▄▄ █▄▄  █  ▄█▄ █▄█ █ ▀▄█      █ ▀▄ █▄▄█ █▄▄ █▄▄ ▄▄█

Kibana client:
Options:
  --ignore-ssl-errors TEXT
  --space TEXT              Kibana space
  --api-key TEXT
  --cloud-id TEXT           ID of the cloud instance.
  --kibana-url TEXT

Usage: detection_rules kibana upload-rule [OPTIONS]

  [Deprecated] Upload a list of rule .toml files to Kibana.

Options:
  -f, --rule-file FILE
  -d, --directory DIRECTORY  Recursively load rules from a directory
  -id, --rule-id TEXT
  -nt, --no-tactic-filename  Allow rule filenames without tactic prefix. Use this if rules have been exported with this flag.
  -r, --replace-id           Replace rule IDs with new IDs before export
  -h, --help                 Show this message and exit.
```

### Exporting rules

This command should be run with the `CUSTOM_RULES_DIR` envvar set, that way proper validation is applied to versioning when the rules are downloaded. See the [custom rules docs](docs-dev/custom-rules-management.md) for more information.

Note: This command can be used for exporting pre-built, customized pre-built, and custom rules. By default, all rules will be exported. Use the `-cro` flag to only export custom rules, or the `-eq` flag to filter by query.

```
python -m detection_rules kibana export-rules -h

█▀▀▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄   ▄      █▀▀▄ ▄  ▄ ▄   ▄▄▄ ▄▄▄
█  █ █▄▄  █  █▄▄ █    █   █  █ █ █▀▄ █      █▄▄▀ █  █ █   █▄▄ █▄▄
█▄▄▀ █▄▄  █  █▄▄ █▄▄  █  ▄█▄ █▄█ █ ▀▄█      █ ▀▄ █▄▄█ █▄▄ █▄▄ ▄▄█

Kibana client:
Options:
  --ignore-ssl-errors TEXT
  --space TEXT              Kibana space
  --api-key TEXT
  --cloud-id TEXT           ID of the cloud instance.
  --kibana-url TEXT

Usage: detection_rules kibana export-rules [OPTIONS]

  Export custom rules from Kibana.

Options:
  -d, --directory PATH            Directory to export rules to  [required]
  -acd, --action-connectors-directory PATH
                                  Directory to export action connectors to
  -ed, --exceptions-directory PATH
                                  Directory to export exceptions to
  -da, --default-author TEXT      Default author for rules missing one
  -r, --rule-id TEXT              Optional Rule IDs to restrict export to
  -rn, --rule-name TEXT           Optional Rule name to restrict export to (KQL, case-insensitive, supports wildcards)
  -ac, --export-action-connectors
                                  Include action connectors in export
  -e, --export-exceptions         Include exceptions in export
  -s, --skip-errors               Skip errors when exporting rules
  -sv, --strip-version            Strip the version fields from all rules
  -nt, --no-tactic-filename       Exclude tactic prefix in exported filenames for rules. Use same flag for import-rules to prevent warnings and disable its unit test.
  -lc, --local-creation-date      Preserve the local creation date of the rule
  -lu, --local-updated-date       Preserve the local updated date of the rule
  -cro, --custom-rules-only       Only export custom rules
  -eq, --export-query TEXT        Apply a query filter to exporting rules e.g. "alert.attributes.tags: \"test\"" to filter for rules that have the tag "test"
  -lr, --load-rule-loading        Enable arbitrary rule loading from the rules directories (Can be very slow!)
  -h, --help                      Show this message and exit.

```

Example of a rule exporting, with errors skipped

```
python -m detection_rules kibana export-rules -d test-export-rules --skip-errors

█▀▀▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄   ▄      █▀▀▄ ▄  ▄ ▄   ▄▄▄ ▄▄▄
█  █ █▄▄  █  █▄▄ █    █   █  █ █ █▀▄ █      █▄▄▀ █  █ █   █▄▄ █▄▄
█▄▄▀ █▄▄  █  █▄▄ █▄▄  █  ▄█▄ █▄█ █ ▀▄█      █ ▀▄ █▄▄█ █▄▄ █▄▄ ▄▄█

- skipping Stolen Credentials Used to Login to Okta Account After MFA Reset - ValidationError
- skipping First Occurrence of Okta User Session Started via Proxy - ValidationError
- skipping ESQL test: cmd child of Explorer - ValidationError
- skipping Potential Persistence Through Run Control Detected - ValidationError
- skipping First Time Seen AWS Secret Value Accessed in Secrets Manager - ValidationError
- skipping Potential Shadow File Read via Command Line Utilities - ValidationError
- skipping Abnormal Process ID or Lock File Created - ValidationError
- skipping New service installed in last 24 hours - ValidationError
- skipping Scheduled Task or Driver added - KqlParseError
- skipping Scheduled Task or Driver removed - KqlParseError
- skipping name - ValidationError
33 rules exported
22 rules converted
22 saved to test-export-rules
11 errors saved to test-export-rules/_errors.txt
```

Directory of the output:

```
ls test-export-rules

_errors.txt
collection_exchange_mailbox_export_via_powershell.toml.toml
credential_access_multiple_okta_user_auth_events_with_same_device_token_hash_behind_a_proxy.toml.toml
credential_access_potential_okta_mfa_bombing_via_push_notifications.toml.toml
defense_evasion_agent_spoofing_multiple_hosts_using_same_agent.toml.toml
defense_evasion_attempt_to_disable_syslog_service.toml.toml
defense_evasion_kernel_module_removal.toml.toml
discovery_enumeration_of_kernel_modules.toml.toml
execution_interactive_terminal_spawned_via_python.toml.toml
initial_access_multiple_okta_client_addresses_for_a_single_user_session.toml.toml
initial_access_new_okta_authentication_behavior_detected.toml.toml
initial_access_okta_fastpass_phishing_detection.toml.toml
initial_access_okta_sign_in_events_via_third_party_idp.toml.toml
initial_access_okta_user_sessions_started_from_different_geolocations.toml.toml
lateral_movement_multiple_okta_sessions_detected_for_a_single_user.toml.toml
my_first_alert.toml.toml
persistence_new_okta_identity_provider_idp_added_by_admin.toml.toml
test_data_view.toml.toml
test_noisy.toml.toml
test_suppress.toml.toml
web_application_suspicious_activity_post_request_declined.toml.toml
web_application_suspicious_activity_sqlmap_user_agent.toml.toml
web_application_suspicious_activity_unauthorized_method.toml.toml
```

Output of the `_errors.txt` file:

```
cat test-export-rules/_errors.txt
- Stolen Credentials Used to Login to Okta Account After MFA Reset - {'_schema': ['Setup header found in both note and setup fields.']}
- First Occurrence of Okta User Session Started via Proxy - {'rule': [ValidationError({'type': ['Must be equal to eql.'], 'language': ['Must be equal to eql.']}), ValidationError({'type': ['Must be equal to esql.'], 'language': ['Must be equal to esql.']}), ValidationError({'type': ['Must be equal to threshold.'], 'threshold': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to threat_match.'], 'threat_mapping': ['Missing data for required field.'], 'threat_index': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to machine_learning.'], 'anomaly_threshold': ['Missing data for required field.'], 'machine_learning_job_id': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to query.']}), ValidationError({'new_terms': ['Missing data for required field.']})]}
- ESQL test: cmd child of Explorer - {'rule': [ValidationError({'type': ['Must be equal to eql.'], 'threat': {0: {'tactic': {'reference': ['String does not match expected pattern.']}, 'technique': {0: {'reference': ['String does not match expected pattern.']}}}}, 'language': ['Must be equal to eql.']}), ValidationError({'threat': {0: {'tactic': {'reference': ['String does not match expected pattern.']}, 'technique': {0: {'reference': ['String does not match expected pattern.']}}}}}), ValidationError({'type': ['Must be equal to threshold.'], 'threat': {0: {'tactic': {'reference': ['String does not match expected pattern.']}, 'technique': {0: {'reference': ['String does not match expected pattern.']}}}}, 'threshold': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to threat_match.'], 'threat': {0: {'tactic': {'reference': ['String does not match expected pattern.']}, 'technique': {0: {'reference': ['String does not match expected pattern.']}}}}, 'threat_mapping': ['Missing data for required field.'], 'threat_index': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to machine_learning.'], 'threat': {0: {'tactic': {'reference': ['String does not match expected pattern.']}, 'technique': {0: {'reference': ['String does not match expected pattern.']}}}}, 'anomaly_threshold': ['Missing data for required field.'], 'machine_learning_job_id': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to query.'], 'threat': {0: {'tactic': {'reference': ['String does not match expected pattern.']}, 'technique': {0: {'reference': ['String does not match expected pattern.']}}}}}), ValidationError({'type': ['Must be equal to new_terms.'], 'threat': {0: {'tactic': {'reference': ['String does not match expected pattern.']}, 'technique': {0: {'reference': ['String does not match expected pattern.']}}}}, 'new_terms': ['Missing data for required field.']})]}
- Potential Persistence Through Run Control Detected - {'rule': [ValidationError({'type': ['Must be equal to eql.'], 'language': ['Must be equal to eql.']}), ValidationError({'type': ['Must be equal to esql.'], 'language': ['Must be equal to esql.']}), ValidationError({'type': ['Must be equal to threshold.'], 'threshold': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to threat_match.'], 'threat_mapping': ['Missing data for required field.'], 'threat_index': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to machine_learning.'], 'anomaly_threshold': ['Missing data for required field.'], 'machine_learning_job_id': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to query.']}), ValidationError({'new_terms': ['Missing data for required field.']})]}
- First Time Seen AWS Secret Value Accessed in Secrets Manager - {'rule': [ValidationError({'type': ['Must be equal to eql.'], 'language': ['Must be equal to eql.']}), ValidationError({'type': ['Must be equal to esql.'], 'language': ['Must be equal to esql.']}), ValidationError({'type': ['Must be equal to threshold.'], 'threshold': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to threat_match.'], 'threat_mapping': ['Missing data for required field.'], 'threat_index': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to machine_learning.'], 'anomaly_threshold': ['Missing data for required field.'], 'machine_learning_job_id': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to query.']}), ValidationError({'new_terms': ['Missing data for required field.']})]}
- Potential Shadow File Read via Command Line Utilities - {'rule': [ValidationError({'type': ['Must be equal to eql.'], 'language': ['Must be equal to eql.']}), ValidationError({'type': ['Must be equal to esql.'], 'language': ['Must be equal to esql.']}), ValidationError({'type': ['Must be equal to threshold.'], 'threshold': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to threat_match.'], 'threat_mapping': ['Missing data for required field.'], 'threat_index': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to machine_learning.'], 'anomaly_threshold': ['Missing data for required field.'], 'machine_learning_job_id': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to query.']}), ValidationError({'new_terms': ['Missing data for required field.']})]}
- Abnormal Process ID or Lock File Created - {'rule': [ValidationError({'type': ['Must be equal to eql.'], 'language': ['Must be equal to eql.']}), ValidationError({'type': ['Must be equal to esql.'], 'language': ['Must be equal to esql.']}), ValidationError({'type': ['Must be equal to threshold.'], 'threshold': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to threat_match.'], 'threat_mapping': ['Missing data for required field.'], 'threat_index': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to machine_learning.'], 'anomaly_threshold': ['Missing data for required field.'], 'machine_learning_job_id': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to query.']}), ValidationError({'new_terms': ['Missing data for required field.']})]}
- New service installed in last 24 hours - {'rule': [ValidationError({'type': ['Must be equal to eql.'], 'language': ['Must be equal to eql.']}), ValidationError({'type': ['Must be equal to esql.'], 'language': ['Must be equal to esql.']}), ValidationError({'type': ['Must be equal to threshold.'], 'threshold': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to threat_match.'], 'threat_mapping': ['Missing data for required field.'], 'threat_index': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to machine_learning.'], 'anomaly_threshold': ['Missing data for required field.'], 'machine_learning_job_id': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to query.']}), ValidationError({'new_terms': ['Missing data for required field.']})]}
- Scheduled Task or Driver added - Error at line:1,column:75
Unknown field
data_stream.dataset:osquery_manager.result and osquery_meta.counter>0 and osquery_meta.type:diff and osquery.last_run_code:0 and osquery_meta.action:added
                                                                          ^^^^^^^^^^^^^^^^^
stack: 8.9.0, beats: 8.9.0, ecs: 8.9.0
- Scheduled Task or Driver removed - Error at line:1,column:75
Unknown field
data_stream.dataset:osquery_manager.result and osquery_meta.counter>0 and osquery_meta.type:diff and osquery.last_run_code:0 and osquery_meta.action:removed
                                                                          ^^^^^^^^^^^^^^^^^
stack: 8.9.0, beats: 8.9.0, ecs: 8.9.0
- name - {'rule': [ValidationError({'type': ['Must be equal to eql.'], 'language': ['Must be equal to eql.']}), ValidationError({'type': ['Must be equal to esql.'], 'language': ['Must be equal to esql.']}), ValidationError({'type': ['Must be equal to threshold.'], 'threshold': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to threat_match.'], 'threat_mapping': ['Missing data for required field.'], 'threat_index': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to machine_learning.'], 'anomaly_threshold': ['Missing data for required field.'], 'machine_learning_job_id': ['Missing data for required field.']}), ValidationError({'type': ['Must be equal to query.']}), ValidationError({'new_terms': ['Missing data for required field.']})]}(venv312) ➜  detection-rules-fork git:(main) ✗
```


## Converting between JSON and TOML

[Importing rules](#importing-rules-into-the-repo) will convert from any supported format to toml. Additionally, the
command `view-rule` will also allow you to view a converted rule without importing it by specifying the `--rule-format` flag.

To view a rule in JSON format, you can also use the `view-rule` command with the `--api-format` flag, which is the default.
(See the [note](#a-note-on-version-handling) on the JSON formatted rules and versioning)


## A note on version handling

The rule toml files exist slightly different than they do in their final state as a JSON file in Kibana. The files are
white space stripped, normalized, sorted, and indented, prior to their json conversion. Everything within the `metadata`
table is also stripped out, as this is meant to be used only in the context of this repository and not in Kibana..

Additionally, the `version` of the rule is added to the file prior to exporting it. This is done to restrict version bumps
to occur intentionally right before we create a release. Versions are auto-incremented based on detected changes in
rules. This is based on the hash of the rule in the following format:
* sorted json
* serialized
* b64 encoded
* sha256 hash

As a result, all cases where rules are shown or converted to JSON are not just simple conversions from TOML.

## Debugging

Most of the CLI errors will print a concise, user friendly error. To enable debug mode and see full error stacktraces,
you can define `"debug": true` in your config file, or run `python -m detection-rules -d <commands...>`.

Precedence goes to the flag over the config file, so if debug is enabled in your config and you run
`python -m detection-rules --no-debug`, debugging will be disabled.


## Using `transform` in rule toml

A transform is any data that will be incorporated into _existing_ rule fields at build time, from within the
`TOMLRuleContents.to_dict` method. _How_ to process each transform should be defined within the `Transform` class as a
method specific to the transform type.

### CLI support for investigation guide plugins

This applies to osquery and insights for the moment but could expand in the future.

```
(venv312) ➜  detection-rules-fork git:(main) python -m detection_rules dev transforms -h

█▀▀▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄   ▄      █▀▀▄ ▄  ▄ ▄   ▄▄▄ ▄▄▄
█  █ █▄▄  █  █▄▄ █    █   █  █ █ █▀▄ █      █▄▄▀ █  █ █   █▄▄ █▄▄
█▄▄▀ █▄▄  █  █▄▄ █▄▄  █  ▄█▄ █▄█ █ ▀▄█      █ ▀▄ █▄▄█ █▄▄ █▄▄ ▄▄█

Usage: detection_rules dev transforms [OPTIONS] COMMAND [ARGS]...

  Commands for managing TOML [transform].

Options:
  -h, --help  Show this message and exit.

Commands:
  guide-plugin-convert  Convert investigation guide plugin format to toml
  guide-plugin-to-rule  Convert investigation guide plugin format to toml
```

`guide-plugin-convert` will print out the formatted toml.


```
(venv312) ➜  detection-rules-fork git:(main) python -m detection_rules dev transforms guide-plugin-convert

█▀▀▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄   ▄      █▀▀▄ ▄  ▄ ▄   ▄▄▄ ▄▄▄
█  █ █▄▄  █  █▄▄ █    █   █  █ █ █▀▄ █      █▄▄▀ █  █ █   █▄▄ █▄▄
█▄▄▀ █▄▄  █  █▄▄ █▄▄  █  ▄█▄ █▄█ █ ▀▄█      █ ▀▄ █▄▄█ █▄▄ █▄▄ ▄▄█

Enter plugin contents []: !{osquery{"query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services\nWHERE NOT (user_account LIKE \"%LocalSystem\" OR user_account LIKE \"%LocalService\" OR user_account LIKE \"%NetworkService\" OR user_account == null)","label":"label2","ecs_mapping":{"labels":{"field":"description"},"agent.build.original":{"value":"fast"}}}}
[transform]

[[transform.osquery]]
query = "SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services\nWHERE NOT (user_account LIKE \"%LocalSystem\" OR user_account LIKE \"%LocalService\" OR user_account LIKE \"%NetworkService\" OR user_account == null)"
label = "label2"

[transform.osquery.ecs_mapping]

[transform.osquery.ecs_mapping.labels]
field = "description"

[transform.osquery.ecs_mapping."agent.build.original"]
value = "fast"
```

The easiest way to _update_ a rule with existing transform entries is to use `guide-plugin-convert` and manually add it
to the rule.
