# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Load rule metadata transform between rule and api formats."""
import functools
import glob
import io
import os
import re
from collections import OrderedDict
from typing import Dict, List

import click
import pytoml

from .mappings import RtaMappings
from .rule import RULES_DIR, Rule
from .schemas import CurrentSchema
from .utils import get_path, cached


RTA_DIR = get_path("rta")
FILE_PATTERN = r'^([a-z0-9_])+\.(json|toml)$'


def mock_loader(f):
    """Mock rule loader."""
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        finally:
            load_rules.clear()

    return wrapped


def reset():
    """Clear all rule caches."""
    load_rule_files.clear()
    load_rules.clear()
    get_rule.clear()
    filter_rules.clear()


@cached
def load_rule_files(verbose=True, paths=None):
    """Load the rule YAML files, but without parsing the EQL query portion."""
    file_lookup = {}  # type: dict[str, dict]

    if verbose:
        print("Loading rules from {}".format(RULES_DIR))

    if paths is None:
        paths = sorted(glob.glob(os.path.join(RULES_DIR, '**', '*.toml'), recursive=True))

    for rule_file in paths:
        try:
            # use pytoml instead of toml because of annoying bugs
            # https://github.com/uiri/toml/issues/152
            # might also be worth looking at https://github.com/sdispater/tomlkit
            with io.open(rule_file, "r", encoding="utf-8") as f:
                file_lookup[rule_file] = pytoml.load(f)
        except Exception:
            print(u"Error loading {}".format(rule_file))
            raise

    if verbose:
        print("Loaded {} rules".format(len(file_lookup)))
    return file_lookup


@cached
def load_rules(file_lookup=None, verbose=True, error=True):
    """Load all the rules from toml files."""
    file_lookup = file_lookup or load_rule_files(verbose=verbose)

    failed = False
    rules: List[Rule] = []
    errors = []
    queries = []
    rule_ids = set()
    rule_names = set()

    for rule_file, rule_contents in file_lookup.items():
        try:
            rule = Rule(rule_file, rule_contents)

            if rule.id in rule_ids:
                raise KeyError("Rule has duplicate ID to {}".format(next(r for r in rules if r.id == rule.id).path))

            if rule.name in rule_names:
                raise KeyError("Rule has duplicate name to {}".format(
                    next(r for r in rules if r.name == rule.name).path))

            parsed_query = rule.parsed_query
            if parsed_query is not None:
                if parsed_query in queries:
                    raise KeyError("Rule has duplicate query with {}".format(
                        next(r for r in rules if r.parsed_query == parsed_query).path))

                queries.append(parsed_query)

            if not re.match(FILE_PATTERN, os.path.basename(rule.path)):
                raise ValueError(f"Rule {rule.path} does not meet rule name standard of {FILE_PATTERN}")

            rules.append(rule)
            rule_ids.add(rule.id)
            rule_names.add(rule.name)

        except Exception as e:
            failed = True
            err_msg = "Invalid rule file in {}\n{}".format(rule_file, click.style(e.args[0], fg='red'))
            errors.append(err_msg)
            if error:
                if verbose:
                    print(err_msg)
                raise e

    if failed:
        if verbose:
            for e in errors:
                print(e)

    return OrderedDict([(rule.id, rule) for rule in sorted(rules, key=lambda r: r.name)])


@cached
def load_gh_pr_rules(labels: list = None, repo: str = 'elastic/detection-rules', token=None, threads=50, verbose=True):
    """Load all rules active as a GitHub PR."""
    import requests
    import pytoml
    from multiprocessing.pool import ThreadPool
    from pathlib import Path
    from .misc import GithubClient

    github = GithubClient(token=token)
    repo = github.client.get_repo(repo)
    labels = set(labels or [])
    open_prs = [r for r in repo.get_pulls() if not labels.difference(set(list(lbl.name for lbl in r.get_labels())))]

    new_rules: List[Rule] = []
    modified_rules: List[Rule] = []
    errors: Dict[str, list] = {}

    existing_rules = load_rules(verbose=False)
    pr_rules = []

    if verbose:
        click.echo('Downloading rules from GitHub PRs')

    def download_worker(pr_info):
        pull, rule_file = pr_info
        response = requests.get(rule_file.raw_url)
        try:
            raw_rule = pytoml.loads(response.text)
            rule = Rule(rule_file.filename, raw_rule)
            rule.gh_pr = pull

            if rule.id in existing_rules:
                modified_rules.append(rule)
            else:
                new_rules.append(rule)

        except Exception as e:
            errors.setdefault(Path(rule_file.filename).name, []).append(str(e))

    for pr in open_prs:
        pr_rules.extend([(pr, f) for f in pr.get_files()
                         if f.filename.startswith('rules/') and f.filename.endswith('.toml')])

    pool = ThreadPool(processes=threads)
    pool.map(download_worker, pr_rules)
    pool.close()
    pool.join()

    new = OrderedDict([(rule.id, rule) for rule in sorted(new_rules, key=lambda r: r.name)])
    modified = OrderedDict()

    for modified_rule in sorted(modified_rules, key=lambda r: r.name):
        modified.setdefault(modified_rule.id, []).append(modified_rule)

    return new, modified, errors


@cached
def get_rule(rule_id=None, rule_name=None, file_name=None, verbose=True):
    """Get a rule based on its id."""
    rules_lookup = load_rules(verbose=verbose)
    if rule_id is not None:
        return rules_lookup.get(rule_id)

    for rule in rules_lookup.values():  # type: Rule
        if rule.name == rule_name:
            return rule
        elif rule.path == file_name:
            return rule


def get_rule_name(rule_id, verbose=True):
    """Get the name of a rule given the rule id."""
    rule = get_rule(rule_id, verbose=verbose)
    if rule:
        return rule.name


def get_file_name(rule_id, verbose=True):
    """Get the file path that corresponds to a rule."""
    rule = get_rule(rule_id, verbose=verbose)
    if rule:
        return rule.path


def get_rule_contents(rule_id, verbose=True):
    """Get the full contents for a rule_id."""
    rule = get_rule(rule_id, verbose=verbose)
    if rule:
        return rule.contents


@cached
def filter_rules(rules, metadata_field, value):
    """Filter rules based on the metadata."""
    return [rule for rule in rules if rule.metadata.get(metadata_field, '') == value]


def get_production_rules(verbose=False):
    """Get rules with a maturity of production."""
    return filter_rules(load_rules(verbose=verbose).values(), 'maturity', 'production')


def find_unneeded_defaults(rule):
    """Remove values that are not required in the schema which are set with default values."""
    schema = CurrentSchema.get_schema(rule.type)
    props = schema['properties']
    unrequired_defaults = [p for p in props if p not in schema['required'] and props[p].get('default')]
    default_matches = {p: rule.contents[p] for p in unrequired_defaults
                       if rule.contents.get(p) and rule.contents[p] == props[p]['default']}
    return default_matches


rta_mappings = RtaMappings()


__all__ = (
    "load_rule_files",
    "load_rules",
    "load_rule_files",
    "load_gh_pr_rules",
    "get_file_name",
    "get_production_rules",
    "get_rule",
    "filter_rules",
    "get_rule_name",
    "get_rule_contents",
    "reset",
    "rta_mappings"
)
