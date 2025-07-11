# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Configuration support for custom components."""

import fnmatch
import os
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any

import yaml
from eql.utils import load_dump  # type: ignore[reportMissingTypeStubs]

from .misc import discover_tests
from .utils import cached, get_etc_path, load_etc_dump, set_all_validation_bypass

ROOT_DIR = Path(__file__).parent.parent
CUSTOM_RULES_DIR = os.getenv("CUSTOM_RULES_DIR", None)


@dataclass
class UnitTest:
    """Base object for unit tests configuration."""

    bypass: list[str] | None = None
    test_only: list[str] | None = None

    def __post_init__(self) -> None:
        if self.bypass and self.test_only:
            raise ValueError("Cannot set both `test_only` and `bypass` in test_config!")


@dataclass
class RuleValidation:
    """Base object for rule validation configuration."""

    bypass: list[str] | None = None
    test_only: list[str] | None = None

    def __post_init__(self) -> None:
        if self.bypass and self.test_only:
            raise ValueError("Cannot use both test_only and bypass")


@dataclass
class ConfigFile:
    """Base object for configuration files."""

    @dataclass
    class FilePaths:
        packages_file: str
        stack_schema_map_file: str
        deprecated_rules_file: str | None = None
        version_lock_file: str | None = None

    @dataclass
    class TestConfigPath:
        config: str

    files: FilePaths
    rule_dir: list[str]
    testing: TestConfigPath | None = None

    @classmethod
    def from_dict(cls, obj: dict[str, Any]) -> "ConfigFile":
        files_data = obj.get("files", {})
        files = cls.FilePaths(
            deprecated_rules_file=files_data.get("deprecated_rules"),
            packages_file=files_data["packages"],
            stack_schema_map_file=files_data["stack_schema_map"],
            version_lock_file=files_data.get("version_lock"),
        )
        rule_dir = obj["rule_dirs"]

        testing_data = obj.get("testing")
        testing = cls.TestConfigPath(config=testing_data["config"]) if testing_data else None

        return cls(files=files, rule_dir=rule_dir, testing=testing)


@dataclass
class TestConfig:
    """Detection rules test config file"""

    test_file: Path | None = None
    unit_tests: UnitTest | None = None
    rule_validation: RuleValidation | None = None

    @classmethod
    def from_dict(
        cls,
        test_file: Path | None = None,
        unit_tests: dict[str, Any] | None = None,
        rule_validation: dict[str, Any] | None = None,
    ) -> "TestConfig":
        return cls(
            test_file=test_file or None,
            unit_tests=UnitTest(**unit_tests or {}),
            rule_validation=RuleValidation(**rule_validation or {}),
        )

    @cached_property
    def all_tests(self) -> list[str]:
        """Get the list of all test names."""
        return discover_tests()

    def tests_by_patterns(self, *patterns: str) -> list[str]:
        """Get the list of test names by patterns."""
        tests: set[str] = set()
        for pattern in patterns:
            tests.update(list(fnmatch.filter(self.all_tests, pattern)))
        return sorted(tests)

    @staticmethod
    def parse_out_patterns(names: list[str]) -> tuple[list[str], list[str]]:
        """Parse out test patterns from a list of test names."""
        patterns: list[str] = []
        tests: list[str] = []
        for name in names:
            if name.startswith("pattern:") and "*" in name:
                patterns.append(name[len("pattern:") :])
            else:
                tests.append(name)
        return patterns, tests

    @staticmethod
    def format_tests(tests: list[str]) -> list[str]:
        """Format unit test names into expected format for direct calling."""
        raw = [t.rsplit(".", maxsplit=2) for t in tests]
        formatted: list[str] = []
        for test in raw:
            path, clazz, method = test
            path = f"{path.replace('.', os.path.sep)}.py"
            formatted.append(f"{path}::{clazz}::{method}")
        return formatted

    def get_test_names(self, formatted: bool = False) -> tuple[list[str], list[str]]:
        """Get the list of test names to run."""
        if not self.unit_tests:
            raise ValueError("No unit tests defined")
        patterns_t, tests_t = self.parse_out_patterns(self.unit_tests.test_only or [])
        patterns_b, tests_b = self.parse_out_patterns(self.unit_tests.bypass or [])
        defined_tests = tests_t + tests_b
        patterns = patterns_t + patterns_b
        unknowns = sorted(set(defined_tests) - set(self.all_tests))
        if unknowns:
            raise ValueError(f"Unrecognized test names in config ({self.test_file}): {unknowns}")

        combined_tests = sorted(set(defined_tests + self.tests_by_patterns(*patterns)))

        if self.unit_tests.test_only is not None:
            tests = combined_tests
            skipped = [t for t in self.all_tests if t not in tests]
        elif self.unit_tests.bypass:
            tests: list[str] = []
            skipped: list[str] = []
            for test in self.all_tests:
                if test not in combined_tests:
                    tests.append(test)
                else:
                    skipped.append(test)
        else:
            tests = self.all_tests
            skipped = []

        if formatted:
            return self.format_tests(tests), self.format_tests(skipped)
        return tests, skipped

    def check_skip_by_rule_id(self, rule_id: str) -> bool:
        """Check if a rule_id should be skipped."""
        if not self.rule_validation:
            raise ValueError("No rule validation specified")
        bypass = self.rule_validation.bypass
        test_only = self.rule_validation.test_only

        # neither bypass nor test_only are defined, so no rules are skipped
        if not (bypass or test_only):
            return False
        # if defined in bypass or not defined in test_only, then skip
        return bool((bypass and rule_id in bypass) or (test_only and rule_id not in test_only))


@dataclass
class RulesConfig:
    """Detection rules config file."""

    deprecated_rules_file: Path
    deprecated_rules: dict[str, dict[str, Any]]
    packages_file: Path
    packages: dict[str, dict[str, Any]]
    rule_dirs: list[Path]
    stack_schema_map_file: Path
    stack_schema_map: dict[str, dict[str, Any]]
    test_config: TestConfig
    version_lock_file: Path
    version_lock: dict[str, dict[str, Any]]

    action_dir: Path | None = None
    action_connector_dir: Path | None = None
    auto_gen_schema_file: Path | None = None
    bbr_rules_dirs: list[Path] = field(default_factory=list)  # type: ignore[reportUnknownVariableType]
    bypass_version_lock: bool = False
    exception_dir: Path | None = None
    normalize_kql_keywords: bool = True
    bypass_optional_elastic_validation: bool = False
    no_tactic_filename: bool = False

    def __post_init__(self) -> None:
        """Perform post validation on packages.yaml file."""
        if "package" not in self.packages:
            raise ValueError("Missing the `package` field defined in packages.yaml.")

        if "name" not in self.packages["package"]:
            raise ValueError("Missing the `name` field defined in packages.yaml.")


@cached
def parse_rules_config(path: Path | None = None) -> RulesConfig:  # noqa: PLR0912, PLR0915
    """Parse the _config.yaml file for default or custom rules."""
    if path:
        if not path.exists():
            raise ValueError(f"rules config file does not exist: {path}")
        loaded = yaml.safe_load(path.read_text())
    elif CUSTOM_RULES_DIR:
        path = Path(CUSTOM_RULES_DIR) / "_config.yaml"
        if not path.exists():
            raise FileNotFoundError(
                """
                Configuration file not found.
                Please create a configuration file. You can use the 'custom-rules setup-config' command
                and update the 'CUSTOM_RULES_DIR' environment variable as needed.
                """
            )
        loaded = yaml.safe_load(path.read_text())
    else:
        path = Path(get_etc_path(["_config.yaml"]))
        loaded = load_etc_dump(["_config.yaml"])

    try:
        _ = ConfigFile.from_dict(loaded)
    except KeyError as e:
        raise SystemExit(f"Missing key `{e!s}` in _config.yaml file.") from e
    except (AttributeError, TypeError) as e:
        raise SystemExit(f"No data properly loaded from {path}") from e
    except ValueError as e:
        raise SystemExit(e) from e

    base_dir = path.resolve().parent

    # testing
    # precedence to the environment variable
    # environment variable is absolute path and config file is relative to the _config.yaml file
    test_config_ev = os.getenv("DETECTION_RULES_TEST_CONFIG", None)
    if test_config_ev:
        test_config_path = Path(test_config_ev)
    else:
        test_config_file = loaded.get("testing", {}).get("config")
        test_config_path = base_dir.joinpath(test_config_file) if test_config_file else None

    if test_config_path:
        test_config_data = yaml.safe_load(test_config_path.read_text())

        # overwrite None with empty list to allow implicit exemption of all tests with `test_only` defined to None in
        # test config
        if "unit_tests" in test_config_data and test_config_data["unit_tests"] is not None:
            test_config_data["unit_tests"] = {k: v or [] for k, v in test_config_data["unit_tests"].items()}
        test_config = TestConfig.from_dict(test_file=test_config_path, **test_config_data)
    else:
        test_config = TestConfig.from_dict()

    # files
    # paths are relative
    files = {f"{k}_file": base_dir.joinpath(v) for k, v in loaded["files"].items()}
    contents = {k: load_dump(str(base_dir.joinpath(v).resolve())) for k, v in loaded["files"].items()}

    contents.update(**files)

    # directories
    # paths are relative
    if loaded.get("directories"):
        contents.update({k: base_dir.joinpath(v).resolve() for k, v in loaded["directories"].items()})

    # rule_dirs
    # paths are relative
    contents["rule_dirs"] = [base_dir.joinpath(d).resolve() for d in loaded.get("rule_dirs")]

    # directories
    # paths are relative
    if loaded.get("directories"):
        directories = loaded.get("directories")
        if directories.get("exception_dir"):
            contents["exception_dir"] = base_dir.joinpath(directories.get("exception_dir")).resolve()
        if directories.get("action_dir"):
            contents["action_dir"] = base_dir.joinpath(directories.get("action_dir")).resolve()
        if directories.get("action_connector_dir"):
            contents["action_connector_dir"] = base_dir.joinpath(directories.get("action_connector_dir")).resolve()

    # version strategy
    contents["bypass_version_lock"] = loaded.get("bypass_version_lock", False)

    # bbr_rules_dirs
    # paths are relative
    if loaded.get("bbr_rules_dirs"):
        contents["bbr_rules_dirs"] = [base_dir.joinpath(d).resolve() for d in loaded.get("bbr_rules_dirs", [])]

    # kql keyword normalization
    contents["normalize_kql_keywords"] = loaded.get("normalize_kql_keywords", True)

    if loaded.get("auto_gen_schema_file"):
        contents["auto_gen_schema_file"] = base_dir.joinpath(loaded["auto_gen_schema_file"])

        # Check if the file exists
        if not contents["auto_gen_schema_file"].exists():
            # If the file doesn't exist, create the necessary directories and file
            contents["auto_gen_schema_file"].parent.mkdir(parents=True, exist_ok=True)
            _ = contents["auto_gen_schema_file"].write_text("{}")

    # bypass_optional_elastic_validation
    contents["bypass_optional_elastic_validation"] = loaded.get("bypass_optional_elastic_validation", False)
    if contents["bypass_optional_elastic_validation"]:
        set_all_validation_bypass(contents["bypass_optional_elastic_validation"])

    # no_tactic_filename
    contents["no_tactic_filename"] = loaded.get("no_tactic_filename", False)

    # return the config
    try:
        rules_config = RulesConfig(test_config=test_config, **contents)  # type: ignore[reportArgumentType]
    except (ValueError, TypeError) as e:
        raise SystemExit(f"Error parsing packages.yaml: {e!s}") from e

    return rules_config


@cached
def load_current_package_version() -> str:
    """Load the current package version from config file."""
    return parse_rules_config().packages["package"]["name"]
