# Command Line Interface

This covers more advanced CLI use cases and workflows. To [get started](README.md#getting-started) with the CLI, reference 
the [readme](README.md). Basic use of the CLI such as [creating a rule](CONTRIBUTING.md#creating-a-rule-with-the-cli) or 
[testing](CONTRIBUTING.md#testing-a-rule-with-the-cli) are referenced in the [contribution guide](CONTRIBUTING.md).


## Using a config file or environment variables

CLI commands which are tied to Kibana and Elasticsearch are capable of parsing auth-related keyword args from a config 
file or environment variables. Any command option which calls `callback=set_param_values` will search for set kwargs.

If a value is set in multiple places, such as config file and environment variable, the order of precedence will be as 
follows:
* explicitly passed args (such as `--user joe`)
* environment variables
* config values
* prompt (this only applies to certain values)

#### Setup a config file

In the root directory of this repo, create the file `.detection-rules-cfg.json` and add relevant values

#### Using environment variables

Environment variables using the key format: `DR_<UPPERCASED_KEY_NAME>` will be parsed in commands which expect it.
EX: `DR_USER=joe`

## Importing rules into the repo

You can import rules into the repo using the `create-rule` or `import-rules` commands. Both of these commands will 
require that the rules are schema-compliant and able to pass full validation. The biggest benefit to using these 
commands is that they will strip[*](#i18n-note) additional fields[**](#i18n-note-2) and prompt for missing required 
fields. 

Alternatively, you can manually place rule files in the directory and run tests to validate as well.

<a id="i18n-note">\* Note</a>: This is currently limited to flat fields and may not apply to nested values.<br>
<a id="i18n-note-2">\** Note</a>: Additional fields are based on the current schema at the time the command is used.


#### `create-rule`

This command will allow you to pass a rule file using the `-c/--config` parameter. This is limited to one rule at a time
and will accept any valid rule in the following formats:
* toml
* json
* yaml (yup)
* ndjson (as long as it contains only a single rule and has the extension `.ndjson` or `.jsonl`)

#### `import-rules`

The primary advantage of using this command is the ability to import multiple rules at once. Multiple rule paths can be
specified explicitly with unlimited arguments, recursively within a directory using `-d/--directory`[*](#i18n-note-3), or 
a combination of both.

In addition to the formats mentioned using `create-rule`, this will also accept an `.ndjson`/`jsonl` file 
containing multiple rules (as would be the case with a bulk export).

This will also strip additional fields and prompt for missing required fields.

<a id="i18n-note-3">\* Note</a>: This will attempt to parse ALL files recursively within a specified directory.


## Uploading rules to Kibana

Toml formatted rule files can be uploaded as custom rules using the `kibana-upload` command. To upload more than one 
file, specify multiple files at a time as individual args.

```console
python -m detection_rules kibana-upload my-rules/example_custom_rule.toml
```

_*Note that in order to load a custom rule, the proper index must be setup first. The simplest way to do this is to click 
the `Load prebuilt detection rules and timeline templates` button on the `detections` page in the Kibana security app._


## Converting between JSON and TOML

[Importing rules](#importing-rules-into-the-repo) will convert from any supported format to toml. Additionally, the 
command `view-rule` will also allow you to view a converted rule without importing it by specifying the `--as-rule` flag.

To view a rule in JSON format, you can also use the `view-rule` command with the `--as-api` flag, which is the default.
(See the [note](#a-note-on-versioning-and-the-generated-json-formatted-rules) on the JSON formatted rules)

Multiple rules can be converted into their JSON representation by using the `build-release` command. This will assemble 
rules which meet the specified filters in the [packages.yml](etc/packages.yml) file and stage them in the generated 
`releases/{release}/rules`
directory.

## A note on versioning and the generated JSON formatted rules

The rule toml files exist slightly different than they do in their final state as a json file in Kibana. The files are
white space stripped, normalized, sorted, and indented, prior to their json conversion. Everything within the `metadata`
table is also stripped out, as this is meant for rule development and management only.

Additionally, the version of the rule is added to the file prior to exporting it. This is done to restrict version bumps
to occur intentionally right before we create a release. Version bumps are auto-incremented based on detected changes in 
rules. This is based on the hash of the rule in the following format:
* sorted json
* serialized
* b64 encoded
* sha256 hash

As a result, all cases where rules are shown or converted to JSON are not just simple conversions from TOML.