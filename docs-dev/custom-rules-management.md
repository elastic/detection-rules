# Custom Rules

A custom rule is any rule that is not maintained by Elastic under `rules/` or `rules_building_block`. These docs are intended
to show how to manage custom rules using this repository.

For more detailed breakdown and explanation of employing a detections-as-code approach, refer to the
[dac-reference](https://dac-reference.readthedocs.io/en/latest/index.html).


## Defining a custom rule config and directory structure

The simplest way to maintain custom rules alongside the existing prebuilt rules in the repo, is to decouple where the rules
are stored to minimize VCS conflicts and overlap. This is accomplished by defining a custom rules directory using a config file.

### Understanding the structure

```
custom-rules
├── _config.yaml
└── rules
    ├── example_rule_1.toml
    ├── example_rule_2.toml
└── etc
    ├── deprecated_rules.json
    ├── packages.yaml
    ├── stack-schema-map.yaml
    ├── test_config.yaml
    └── version.lock.json
└── actions
    ├── action_1.toml
    ├── action_2.toml
└── action_connectors
    ├── action_connector_1.toml
    └── action_connectors_2.toml    
└── exceptions
    ├── exception_1.toml
    └── exception_2.toml
```

This structure represents a portable set of custom rules. This is just an example, and the exact locations of the files
should be defined in the `_config.yaml` file. Refer to the details in the default
[_config.yaml](../detection_rules/etc/_config.yaml) for more information.

* deprecated_rules.json - tracks all deprecated rules (optional)
* packages.yaml - information for building packages (mostly optional, but the current version is required)
* stack-schema-map.yaml - a mapping of schemas for query validation
* test_config.yaml - a config file for testing (optional)
* version.lock.json - this tracks versioning for rules (optional depending on versioning strategy)

To initialize a custom rule directory, run `python -m detection_rules custom-rules setup-config <directory>`

### Defining a config

```yaml
rule_dirs:
  - rules
files:
  deprecated_rules: deprecated_rules.json
  packages: packages.yaml
  stack_schema_map: stack-schema-map.yaml
  version_lock: version.lock.json
directories:
  action_dir: actions
  action_connector_dir: action_connectors
  exception_dir: exceptions
```

Some notes:

* The paths in this file are relative to the custom rules directory (CUSTOM_RULES_DIR/)
* Refer to each original [source file](../detection_rules/etc/example_test_config.yaml) for purpose and proper formatting
* You can also add an optional `bbr_rules_dirs` section for custom BBR rules.
* To bypass using the version lock versioning strategy (version lock file) you can set the optional `bypass_version_lock` value to be `True`
* To normalize the capitalization KQL keywords in KQL rule queries one can use the optional `normalize_kql_keywords` value set to `True` or `False` as desired.
* To manage exceptions tied to rules one can set an exceptions directory using the optional `exception_dir` value (included above) set to be the desired path. If an exceptions directory is explicitly specified in a CLI command, the config value will be ignored.
* To manage action-connectors tied to rules one can set an action-connectors directory using the optional `action_connector_dir` value (included above) set to be the desired path. If an actions_connector directory is explicitly specified in a CLI command, the config value will be ignored.
* To turn on automatic schema generation for non-ecs fields via custom schemas add `auto_gen_schema_file: <path_to_your_json_file>`. This will generate a schema file in the specified location that will be used to add entries for each field and index combination that is not already in a known schema. This will also automatically add it to your stack-schema-map.yaml file when using a custom rules directory and config.
* For Kibana action items, currently these are included in the rule toml files themselves. At a later date, we may allow for bulk editing of rule action items through separate action toml files. The action_dir config key is left available for this later implementation. For now to bulk update, use the bulk actions add rule actions UI in Kibana.
* To on bulk disable elastic validation for optional fields, use the following line `bypass_optional_elastic_validation: True`.


When using the repo, set the environment variable `CUSTOM_RULES_DIR=<directory-with-_config.yaml>`


### Defining a testing config

```yaml
testing:
  config: etc/example_test_config.yaml
```

This points to the testing config file (see example under detection_rules/etc/example_test_config.yaml) and can either
be set in `_config.yaml` or as the environment variable `DETECTION_RULES_TEST_CONFIG`, with precedence going to the
environment variable if both are set. Having both these options allows for configuring testing on prebuilt Elastic rules
without specifying a rules _config.yaml.

Some notes:

* If set in this file, the path should be relative to the location of this config. If passed as an environment variable, it should be the full path
* When using the `--no-tactic-filename` flag for kibana imports and exports, be sure to disable the unit test by using the following line `- tests.test_all_rules.TestRuleFiles.test_rule_file_name_tactic` in your test config file.


### How the config is used and it's designed portability

This repo is designed to operate on certain expectations of structure and config files. By defining the code below, it allows
the design to become portable and based on defined information, rather than the static excpectiations.

```python
RULES_CONFIG = parse_rules_config()

# which then makes the following attribute available for use

@dataclass
class RulesConfig:
    """Detection rules config file."""
    deprecated_rules_file: Path
    deprecated_rules: Dict[str, dict]
    packages_file: Path
    packages: Dict[str, dict]
    rule_dirs: List[Path]
    stack_schema_map_file: Path
    stack_schema_map: Dict[str, dict]
    test_config: TestConfig
    version_lock_file: Path
    version_lock: Dict[str, dict]

    action_dir: Optional[Path] = None
    action_connector_dir: Optional[Path] = None
    auto_gen_schema_file: Optional[Path] = None
    bbr_rules_dirs: Optional[List[Path]] = field(default_factory=list)
    bypass_version_lock: bool = False
    exception_dir: Optional[Path] = None
    normalize_kql_keywords: bool = True
    bypass_optional_elastic_validation: bool = False

# using the stack_schema_map
RULES_CONFIG.stack_schema_map
```

### Version Strategy Warning

- General (`bypass_version_lock = False`)
  - Default
  - Versions from Kibana or the TOML file are ignored
  - Version lock file usage is permitted
- General (`bypass_version_lock = True`)
  - Must be explicitly set in the config
  - Versions from Kibana or the TOML file are used
  - Version lock file usage is not permitted
- Tactical Warning Messages
  - Rule import to TOML file will skip version and revision fields when supplied (*rule_prompt* & *import_rules_into_repo*) if `bypass_version_lock = False`. No warning message is issued.
  - Rule version lock will not be updated or used if `bypass_version_lock = True` when building a release package (*build_release*). A warning message is issued.
  - If versions are in the TOML file, and `bypass_version_lock = False`, the versions in the TOML file will not be used (*autobumped_version*). A warning message is issued.
  - If `bypass_version_lock = False`, when autobumping the version, it will check the version lock file and increment if is_dirty (*autobumped_version*), otherwise just use the version supplied. No warning message is issued.
  - If `bypass_version_lock = True`, the updating the version lock file will disabled (*update_lock_versions*). A warning message is issued.
  - If `bypass_version_lock = True`, loading the version lock file is disabled and skipped. (*from_dict*, *load_from_file*, *manage_versions*, *test_version_lock_has_nested_previous*). A warning message is issued.

### Custom actions, action connectors, and exceptions lists

To convert these to TOML, you can do the following:

1. export the ndjson from Kibana into a `dict` or load from kibana

```python
from detection_rules.action import Action, ActionMeta, TOMLActionContents, TOMLAction

action = Action.from_dict(action_dict)
meta = ActionMeta(...)
action_contents = TOMLActionContents(action=[action], meta=meta)
toml_action = TOMLAction(path=Path, contents=action_contents)
```

Mimick a similar approach for exception lists. Both can then be managed with the `GenericLoader`

```python
from detection_rules.generic_loader import GenericLoader

loader = GenericLoader()
loader.load_directory(...)
```

### Using Custom Schemas

You can specify custom defined schemas for custom indexes using the `etc/stack-schema-map.yaml` in your custom rules directory.

To add a custom schema, add a sub key in the `etc/stack-schema-map.yaml` file under the stack version you wish the custom schema to apply.
Then for its value, reference the json file, or folder of files, where you have your schema defined. Please note, to validate rules with a `min_stack_version` set, the `stack-schema-map.yaml` needs an entry for the highest version.

Example:

```yaml
8.14.0:
  beats: 8.12.2
  ecs: 8.11.0
  endgame: 8.4.0
  custom: schemas/custom-schema.json
```

Note: the `custom` key can be any alpha numeric value except `beats`, `ecs`, or `endgame` as these are reserved terms. 

Note: Remember if you want to turn on automatic schema generation for non-ecs fields a custom schemas add `auto_gen_schema_file: <path_to_your_json_file>`. 

Example schema json:

```json

{
    "custom-index*": {
      "process.NewCustomValue": "keyword",
      "process.AnotherCustomValue": "keyword"
    }
}
```

This can then be used in a rule query by adding the index to the applicable rule e.g. `index = ["logs-endpoint.events.*", "custom-index*"]`.
Then one can use the index in the query e.g. `process where host.os.type == "linux" and process.NewCustomValue == "GoodValue"`