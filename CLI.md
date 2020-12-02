# Command Line Interface (CLI)

This covers more advanced CLI use cases and workflows. To [get started](README.md#getting-started) with the CLI, reference 
the [README](README.md). Basic use of the CLI such as [creating a rule](CONTRIBUTING.md#creating-a-rule-with-the-cli) or 
[testing](CONTRIBUTING.md#testing-a-rule-with-the-cli) are referenced in the [contribution guide](CONTRIBUTING.md).


## Using a config file or environment variables

CLI commands which are tied to Kibana and Elasticsearch are capable of parsing auth-related keyword args from a config 
file or environment variables. 

If a value is set in multiple places, such as config file and environment variable, the order of precedence will be as 
follows:
* explicitly passed args (such as `--user joe`)
* environment variables
* config values
* prompt (this only applies to certain values)

#### Setup a config file

In the root directory of this repo, create the file `.detection-rules-cfg.json` and add relevant values

Currently supported arguments:
* elasticsearch_url
* kibana_url
* cloud_id
* *_username (kibana and es)
* *_password (kibana and es)

#### Using environment variables

Environment variables using the argument format: `DR_<UPPERCASED_ARG_NAME>` will be parsed in commands which expect it.
EX: `DR_USER=joe`

## Importing rules into the repo

You can import rules into the repo using the `create-rule` or `import-rules` commands. Both of these commands will 
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
  -t, --rule-type [machine_learning|saved_query|query|threshold]
                                  Type of rule to create
  -h, --help                      Show this message and exit.
```

This command will allow you to pass a rule file using the `-c/--config` parameter. This is limited to one rule at a time
and will accept any valid rule in the following formats:
* toml
* json
* yaml (yup)
* ndjson (as long as it contains only a single rule and has the extension `.ndjson` or `.jsonl`)

#### `import-rules`

```console
Usage: detection_rules import-rules [OPTIONS] [INFILE]...

  Import rules from json, toml, or Kibana exported rule file(s).

Options:
  -d, --directory DIRECTORY  Load files from a directory
  -h, --help                 Show this message and exit.
```

The primary advantage of using this command is the ability to import multiple rules at once. Multiple rule paths can be
specified explicitly with unlimited arguments, recursively within a directory using `-d/--directory`[*](#note-3), or 
a combination of both.

In addition to the formats mentioned using `create-rule`, this will also accept an `.ndjson`/`jsonl` file 
containing multiple rules (as would be the case with a bulk export).

This will also strip additional fields and prompt for missing required fields.

<a id="note-3">\* Note</a>: This will attempt to parse ALL files recursively within a specified directory.


## Commands using Elasticsearch and Kibana clients

Commands which connect to Elasticsearch or Kibana are embedded under the subcommands:
* es
* kibana

These command groups will leverage their respective clients and will automatically use parsed config options if
defined, otherwise arguments should be passed to the sub-command as:

`python -m detection-rules kibana -u <username> -p <password> upload-rule <...>`

```console
python -m detection_rules es -h

Usage: detection_rules es [OPTIONS] COMMAND [ARGS]...

  Commands for integrating with Elasticsearch.

Options:
  -et, --timeout INTEGER        Timeout for elasticsearch client
  -ep, --es-password TEXT
  -eu, --es-user TEXT
  --cloud-id TEXT
  -e, --elasticsearch-url TEXT
  -h, --help                    Show this message and exit.

Commands:
  collect-events  Collect events from Elasticsearch.
```

```console
python -m detection_rules kibana -h

Usage: detection_rules kibana [OPTIONS] COMMAND [ARGS]...

  Commands for integrating with Kibana.

Options:
  --space TEXT                 Kibana space
  -kp, --kibana-password TEXT
  -ku, --kibana-user TEXT
  --cloud-id TEXT
  -k, --kibana-url TEXT
  -h, --help                   Show this message and exit.

Commands:
  upload-rule  Upload a list of rule .toml files to Kibana.
```


## Uploading rules to Kibana

Toml formatted rule files can be uploaded as custom rules using the `kibana upload-rule` command. To upload more than one 
file, specify multiple files at a time as individual args. This command is meant to support uploading and testing of 
rules and is not intended for production use in its current state.

```console
python -m detection_rules kibana upload-rule -h

Kibana client:
Options:
  --space TEXT                 Kibana space
  -kp, --kibana-password TEXT
  -ku, --kibana-user TEXT
  --cloud-id TEXT
  -k, --kibana-url TEXT

Usage: detection_rules kibana upload-rule [OPTIONS] TOML_FILES...

  Upload a list of rule .toml files to Kibana.

Options:
  -h, --help  Show this message and exit.
```

_*To load a custom rule, the proper index must be setup first. The simplest way to do this is to click 
the `Load prebuilt detection rules and timeline templates` button on the `detections` page in the Kibana security app._


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
