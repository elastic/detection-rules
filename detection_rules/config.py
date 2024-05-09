# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Configuration support for custom components."""
import fnmatch
import os
from dataclasses import dataclass
from pathlib import Path
from functools import cached_property
from typing import Dict, List, Optional

import yaml
from eql.utils import load_dump

from .misc import discover_tests
from .utils import cached, load_etc_dump, get_etc_path

ROOT_DIR = Path(__file__).parent.parent
CUSTOM_RULES_DIR = os.getenv('CUSTOM_RULES_DIR', None)


@dataclass
class UnitTest:
    """Base object for unit tests configuration."""
    bypass: Optional[List[str]] = None
    test_only: Optional[List[str]] = None

    def __post_init__(self):
        assert not (self.bypass and self.test_only), 'Cannot use both test_only and bypass'


@dataclass
class RuleValidation:
    """Base object for rule validation configuration."""
    bypass: Optional[List[str]] = None
    test_only: Optional[List[str]] = None

    def __post_init__(self):
        assert not (self.bypass and self.test_only), 'Cannot use both test_only and bypass'


@dataclass
class TestConfig:
    """Detection rules test config file"""
    test_file: Optional[Path] = None
    unit_tests: Optional[UnitTest] = None
    rule_validation: Optional[RuleValidation] = None

    @classmethod
    def from_dict(cls, test_file: Optional[Path] = None, unit_tests: Optional[dict] = None,
                  rule_validation: Optional[dict] = None):
        return cls(test_file=test_file or None, unit_tests=UnitTest(**unit_tests or {}),
                   rule_validation=RuleValidation(**rule_validation or {}))

    @cached_property
    def all_tests(self):
        """Get the list of all test names."""
        return discover_tests()

    def tests_by_patterns(self, *patterns: str) -> List[str]:
        """Get the list of test names by patterns."""
        tests = set()
        for pattern in patterns:
            tests.update(list(fnmatch.filter(self.all_tests, pattern)))
        return sorted(tests)

    @staticmethod
    def parse_out_patterns(names: List[str]) -> (List[str], List[str]):
        """Parse out test patterns from a list of test names."""
        patterns = []
        tests = []
        for name in names:
            if name.startswith('pattern:') and '*' in name:
                patterns.append(name[len('pattern:'):])
            else:
                tests.append(name)
        return patterns, tests

    @staticmethod
    def format_tests(tests: List[str]) -> List[str]:
        """Format unit test names into expected format for direct calling."""
        raw = [t.rsplit('.', maxsplit=2) for t in tests]
        formatted = []
        for test in raw:
            path, clazz, method = test
            path = f'{path.replace(".", os.path.sep)}.py'
            formatted.append('::'.join([path, clazz, method]))
        return formatted

    def get_test_names(self, formatted: bool = False) -> (List[str], List[str]):
        """Get the list of test names to run."""
        patterns_t, tests_t = self.parse_out_patterns(self.unit_tests.test_only or [])
        patterns_b, tests_b = self.parse_out_patterns(self.unit_tests.bypass or [])
        defined_tests = tests_t + tests_b
        patterns = patterns_t + patterns_b
        unknowns = sorted(set(defined_tests) - set(self.all_tests))
        assert not unknowns, f'Unrecognized test names in config ({self.test_file}): {unknowns}'

        combined_tests = sorted(set(defined_tests + self.tests_by_patterns(*patterns)))

        if self.unit_tests.test_only is not None:
            tests = combined_tests
            skipped = [t for t in self.all_tests if t not in tests]
        elif self.unit_tests.bypass:
            tests = []
            skipped = []
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
        else:
            return tests, skipped

    def check_skip_by_rule_id(self, rule_id: str) -> bool:
        """Check if a rule_id should be skipped."""
        bypass = self.rule_validation.bypass
        test_only = self.rule_validation.test_only

        # neither bypass nor test_only are defined, so no rules are skipped
        if not (bypass or test_only):
            return False
        # if defined in bypass or not defined in test_only, then skip
        return (bypass and rule_id in bypass) or (test_only and rule_id not in test_only)


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
    exception_dir: Optional[Path] = None


@cached
def parse_rules_config(path: Optional[Path] = None) -> RulesConfig:
    """Parse the _config.yaml file for default or custom rules."""
    if path:
        assert path.exists(), f'rules config file does not exist: {path}'
        loaded = yaml.safe_load(path.read_text())
    elif CUSTOM_RULES_DIR:
        path = Path(CUSTOM_RULES_DIR) / '_config.yaml'
        assert path.exists(), f'_config.yaml file missing in {CUSTOM_RULES_DIR}'
        loaded = yaml.safe_load(path.read_text())
    else:
        path = Path(get_etc_path('_config.yaml'))
        loaded = load_etc_dump('_config.yaml')

    assert loaded, f'No data loaded from {path}'

    base_dir = path.resolve().parent

    # testing
    # precedence to the environment variable
    # environment variable is absolute path and config file is relative to the _config.yaml file
    test_config_ev = os.getenv('DETECTION_RULES_TEST_CONFIG', None)
    if test_config_ev:
        test_config_path = Path(test_config_ev)
    else:
        test_config_file = loaded.get('testing', {}).get('config')
        if test_config_file:
            test_config_path = base_dir.joinpath(test_config_file)
        else:
            test_config_path = None

    if test_config_path:
        test_config_data = yaml.safe_load(test_config_path.read_text())

        # overwrite None with empty list to allow implicit exemption of all tests with `test_only` defined to None in
        # test config
        if 'unit_tests' in test_config_data and test_config_data['unit_tests'] is not None:
            test_config_data['unit_tests'] = {k: v or [] for k, v in test_config_data['unit_tests'].items()}
        test_config = TestConfig.from_dict(test_file=test_config_path, **test_config_data)
    else:
        test_config = TestConfig.from_dict()

    # files
    # paths are relative
    files = {f'{k}_file': base_dir.joinpath(v) for k, v in loaded['files'].items()}
    contents = {k: load_dump(str(base_dir.joinpath(v))) for k, v in loaded['files'].items()}
    contents.update(**files)

    # directories
    # paths are relative
    if loaded.get('directories'):
        contents.update({k: base_dir.joinpath(v) for k, v in loaded['directories'].items()})

    # rule_dirs
    # paths are relative
    contents['rule_dirs'] = [base_dir.joinpath(d).resolve() for d in loaded.get('rule_dirs', [])]

    rules_config = RulesConfig(test_config=test_config, **contents)
    return rules_config


@cached
def load_current_package_version() -> str:
    """Load the current package version from config file."""
    return parse_rules_config().packages['package']['name']
