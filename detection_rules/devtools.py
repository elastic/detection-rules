# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""CLI commands for internal detection_rules dev team."""

import csv
import dataclasses
import json
import os
import re
import shutil
import subprocess
import textwrap
import time
import typing
import urllib.parse
from collections import defaultdict
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

import click
import pytoml  # type: ignore[reportMissingTypeStubs]
import requests.exceptions
import yaml
from elasticsearch import BadRequestError, Elasticsearch
from elasticsearch import ConnectionError as ESConnectionError
from eql.table import Table  # type: ignore[reportMissingTypeStubs]
from eql.utils import load_dump  # type: ignore[reportMissingTypeStubs, reportUnknownVariableType]
from semver import Version

from kibana.connector import Kibana  # type: ignore[reportMissingTypeStubs]
from kibana.resources import Signal  # type: ignore[reportMissingTypeStubs]

from . import attack, rule_loader, utils
from .beats import download_beats_schema, download_latest_beats_schema, refresh_main_schema
from .cli_utils import single_collection
from .config import parse_rules_config
from .docs import REPO_DOCS_DIR, IntegrationSecurityDocs, IntegrationSecurityDocsMDX
from .ecs import download_endpoint_schemas, download_schemas
from .endgame import EndgameSchemaManager
from .esql_errors import (
    ESQL_EXCEPTION_TYPES,
)
from .eswrap import CollectEvents, add_range_to_dsl
from .ghwrap import GithubClient, update_gist
from .integrations import (
    SecurityDetectionEngine,
    build_integrations_manifest,
    build_integrations_schemas,
    find_latest_compatible_version,
    find_latest_integration_version,
    load_integrations_manifests,
)
from .main import root
from .misc import (
    PYTHON_LICENSE,
    add_client,
    get_default_elasticsearch_client,
    get_default_kibana_client,
    raise_client_error,
)
from .packaging import CURRENT_RELEASE_PATH, PACKAGE_FILE, RELEASE_DIR, Package
from .rule import (
    AnyRuleData,
    BaseRuleData,
    DeprecatedRule,
    QueryRuleData,
    RuleTransform,
    ThreatMapping,
    TOMLRule,
    TOMLRuleContents,
)
from .rule_loader import RuleCollection, production_filter
from .rule_validators import ESQLValidator
from .schemas import definitions, get_stack_versions
from .utils import check_version_lock_double_bumps, dict_hash, get_etc_path, get_path
from .version_lock import VersionLockFile, loaded_version_lock

GH_CONFIG = Path.home() / ".config" / "gh" / "hosts.yml"
NAVIGATOR_GIST_ID = "0443cfb5016bed103f1940b2f336e45a"
NAVIGATOR_URL = "https://ela.st/detection-rules-navigator-trade"
NAVIGATOR_BADGE = (
    f"[![ATT&CK navigator coverage](https://img.shields.io/badge/ATT&CK-Navigator-red.svg)]({NAVIGATOR_URL})"
)
RULES_CONFIG = parse_rules_config()

# The rule diff feature is available in 8.18 but needs to be tested in pre-release versions
MIN_DIFF_FEATURE_VERSION = Version(major=8, minor=17, patch=0)

# The caps for the historical versions of the rules
MAX_HISTORICAL_VERSIONS_FOR_DIFF = 3
MAX_HISTORICAL_VERSIONS_PRE_DIFF = 1


def get_github_token() -> str | None:
    """Get the current user's GitHub token."""
    token = os.getenv("GITHUB_TOKEN")

    if token is None and GH_CONFIG.exists():
        token = load_dump(str(GH_CONFIG)).get("github.com", {}).get("oauth_token")

    return token


@root.group("dev")
def dev_group() -> None:
    """Commands related to the Elastic Stack rules release lifecycle."""


@dev_group.command("build-release")
@click.argument(
    "config-file", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=False, default=PACKAGE_FILE
)
@click.option(
    "--update-version-lock",
    "-u",
    is_flag=True,
    help="Save version.lock.json file with updated rule versions in the package",
)
@click.option("--generate-navigator", is_flag=True, help="Generate ATT&CK navigator files")
@click.option("--generate-docs", is_flag=True, default=False, help="Generate markdown documentation")
@click.option("--update-message", type=str, help="Update message for new package")
@click.pass_context
def build_release(  # noqa: PLR0913
    ctx: click.Context,
    config_file: Path,
    update_version_lock: bool,
    generate_navigator: bool,
    generate_docs: str,
    update_message: str,
    release: str | None = None,
    verbose: bool = True,
) -> Package:
    """Assemble all the rules into Kibana-ready release files."""
    if RULES_CONFIG.bypass_version_lock:
        click.echo(
            "WARNING: You cannot run this command when the versioning strategy is configured to bypass the "
            "version lock. Set `bypass_version_lock` to `False` in the rules config to use the version lock."
        )
        ctx.exit()

    config = load_dump(str(config_file))["package"]

    package_path = get_etc_path(["package.yaml"])
    if "registry_data" not in config:
        raise ValueError(
            f"No `registry_data` in package config. Please see the {package_path} file for an"
            f" example on how to supply this field in {PACKAGE_FILE}."
        )

    registry_data = config["registry_data"]

    if generate_navigator:
        config["generate_navigator"] = True

    if release is not None:
        config["release"] = release

    if verbose:
        click.echo(f"[+] Building package {config.get('name')}")

    package = Package.from_config(config=config, verbose=verbose)

    if update_version_lock:
        _ = loaded_version_lock.manage_versions(package.rules, save_changes=True, verbose=verbose)

    package.save(verbose=verbose)

    previous_pkg_version = find_latest_integration_version(
        "security_detection_engine", "ga", registry_data["conditions"]["kibana.version"].strip("^")
    )
    sde = SecurityDetectionEngine()
    historical_rules = sde.load_integration_assets(previous_pkg_version)
    current_pkg_version = Version.parse(registry_data["version"])
    # pre-release versions are not included in the version comparison
    # Version 8.17.0-beta.1 is considered lower than 8.17.0
    current_pkg_version_no_prerelease = Version(
        major=current_pkg_version.major, minor=current_pkg_version.minor, patch=current_pkg_version.patch
    )

    hist_versions_num = (
        MAX_HISTORICAL_VERSIONS_FOR_DIFF
        if current_pkg_version_no_prerelease >= MIN_DIFF_FEATURE_VERSION
        else MAX_HISTORICAL_VERSIONS_PRE_DIFF
    )
    click.echo(
        "[+] Limit historical rule versions in the release package for "
        f"version {current_pkg_version_no_prerelease}: {hist_versions_num} versions"
    )
    limited_historical_rules = sde.keep_latest_versions(historical_rules, num_versions=hist_versions_num)

    _ = package.add_historical_rules(limited_historical_rules, registry_data["version"])
    click.echo(f"[+] Adding historical rules from {previous_pkg_version} package")

    # NOTE: stopgap solution until security doc migration
    if generate_docs:
        click.echo(f"[+] Generating security docs for {registry_data['version']} package")
        docs = IntegrationSecurityDocsMDX(
            registry_data["version"],
            Path(f"releases/{config['name']}-docs"),
            True,
            package,
            limited_historical_rules,
            note=update_message,
        )
        _ = docs.generate()

    if verbose:
        _ = package.get_package_hash(verbose=verbose)
        click.echo(f"- {len(package.rules)} rules included")

    return package


def get_release_diff(
    pre: str,
    post: str,
    remote: str = "origin",
) -> tuple[dict[str, TOMLRule], dict[str, TOMLRule], dict[str, DeprecatedRule]]:
    """Build documents from two git tags for an integration package."""
    pre_rules = RuleCollection()
    pre_rules.load_git_tag(f"integration-v{pre}", remote, skip_query_validation=True)

    if pre_rules.errors:
        click.echo(f"error loading {len(pre_rules.errors)} rule(s) from: {pre}, skipping:")
        click.echo(" - " + "\n - ".join([str(p) for p in pre_rules.errors]))

    post_rules = RuleCollection()
    post_rules.load_git_tag(f"integration-v{post}", remote, skip_query_validation=True)

    if post_rules.errors:
        click.echo(f"error loading {len(post_rules.errors)} rule(s) from: {post}, skipping:")
        click.echo(" - " + "\n - ".join([str(p) for p in post_rules.errors]))

    return pre_rules.compare_collections(post_rules)


@dev_group.command("build-integration-docs")
@click.argument("registry-version")
@click.option("--pre", required=True, type=str, help="Tag for pre-existing rules")
@click.option("--post", required=True, type=str, help="Tag for rules post updates")
@click.option("--directory", "-d", type=Path, required=True, help="Output directory to save docs to")
@click.option("--force", "-f", is_flag=True, help="Bypass the confirmation prompt")
@click.option("--remote", "-r", default="origin", help='Override the remote from "origin"')
@click.option("--update-message", default="Rule Updates.", type=str, help="Update message for new package")
@click.pass_context
def build_integration_docs(  # noqa: PLR0913
    ctx: click.Context,
    registry_version: str,
    pre: str,
    post: str,
    directory: Path,
    force: bool,
    update_message: str,
    remote: str = "origin",
) -> IntegrationSecurityDocs:
    """Build documents from two git tags for an integration package."""
    if not force and not click.confirm(
        f"This will refresh tags and may overwrite local tags for: {pre} and {post}. Continue?"
    ):
        ctx.exit(1)

    if Version.parse(pre) >= Version.parse(post):
        raise ValueError(f"pre: {pre} is not less than post: {post}")

    if not Version.parse(pre):
        raise ValueError(f"pre: {pre} is not a valid semver")

    if not Version.parse(post):
        raise ValueError(f"post: {post} is not a valid semver")

    rules_changes = get_release_diff(pre, post, remote)
    docs = IntegrationSecurityDocs(
        registry_version,
        directory,
        True,
        *rules_changes,
        update_message=update_message,
    )
    package_dir = docs.generate()

    click.echo(f"Generated documents saved to: {package_dir}")
    updated, new, deprecated = rules_changes
    click.echo(f"- {len(updated)} updated rules")
    click.echo(f"- {len(new)} new rules")
    click.echo(f"- {len(deprecated)} deprecated rules")

    return docs


@dev_group.command("bump-pkg-versions")
@click.option("--major-release", is_flag=True, help="bump the major version")
@click.option("--minor-release", is_flag=True, help="bump the minor version")
@click.option("--patch-release", is_flag=True, help="bump the patch version")
@click.option("--new-package", type=click.Choice(["true", "false"]), help="indicates new package")
@click.option(
    "--maturity",
    type=click.Choice(["beta", "ga"], case_sensitive=False),
    required=True,
    help="beta or production versions",
)
def bump_versions(
    major_release: bool,
    minor_release: bool,
    patch_release: bool,
    new_package: str,
    maturity: str,
) -> None:
    """Bump the versions"""

    pkg_data = RULES_CONFIG.packages["package"]
    kibana_ver = Version.parse(pkg_data["name"], optional_minor_and_patch=True)
    pkg_ver = Version.parse(pkg_data["registry_data"]["version"])
    pkg_kibana_ver = Version.parse(pkg_data["registry_data"]["conditions"]["kibana.version"].lstrip("^"))
    if major_release:
        major_bump = kibana_ver.bump_major()
        pkg_data["name"] = f"{major_bump.major}.{major_bump.minor}"
        pkg_data["registry_data"]["conditions"]["kibana.version"] = f"^{pkg_kibana_ver.bump_major()}"
        pkg_data["registry_data"]["version"] = str(pkg_ver.bump_major().bump_prerelease("beta"))
    if minor_release:
        minor_bump = kibana_ver.bump_minor()
        pkg_data["name"] = f"{minor_bump.major}.{minor_bump.minor}"
        pkg_data["registry_data"]["conditions"]["kibana.version"] = f"^{pkg_kibana_ver.bump_minor()}"
        pkg_data["registry_data"]["version"] = str(pkg_ver.bump_minor().bump_prerelease("beta"))
    if patch_release:
        latest_patch_release_ver = find_latest_integration_version(
            "security_detection_engine", maturity, pkg_kibana_ver
        )

        # if an existing minor or major does not have a package, bump from the last
        # example is 8.10.0-beta.1 is last, but on 9.0.0 major
        # example is 8.10.0-beta.1 is last, but on 8.11.0 minor
        if latest_patch_release_ver.minor != pkg_kibana_ver.minor:
            latest_patch_release_ver = latest_patch_release_ver.bump_minor()
        if latest_patch_release_ver.major != pkg_kibana_ver.major:
            latest_patch_release_ver = latest_patch_release_ver.bump_major()

        if maturity == "ga":
            pkg_data["registry_data"]["version"] = str(latest_patch_release_ver.bump_patch())
        else:
            # passing in true or false from GH actions; not using eval() for security purposes
            if new_package == "true":
                latest_patch_release_ver = latest_patch_release_ver.bump_patch()
            pkg_data["registry_data"]["version"] = str(latest_patch_release_ver.bump_prerelease("beta"))

        if "release" in pkg_data["registry_data"]:
            pkg_data["registry_data"]["release"] = maturity

    click.echo(f"Kibana version: {pkg_data['name']}")
    click.echo(f"Package Kibana version: {pkg_data['registry_data']['conditions']['kibana.version']}")
    click.echo(f"Package version: {pkg_data['registry_data']['version']}")

    RULES_CONFIG.packages_file.write_text(yaml.safe_dump({"package": pkg_data}))


@dev_group.command("check-version-lock")
@click.option("--pr-number", type=int, help="Pull request number to fetch the version lock file from")
@click.option(
    "--local-file",
    type=str,
    default="detection_rules/etc/version.lock.json",
    help="Path to the local version lock file (default: detection_rules/etc/version.lock.json)",
)
@click.option(
    "--token",
    required=True,
    prompt=get_github_token() is None,
    default=get_github_token(),
    help="GitHub token to use for the PR",
    hide_input=True,
)
@click.option("--comment", is_flag=True, help="If set, enables commenting on the PR (requires --pr-number)")
@click.option("--save-double-bumps", type=Path, help="Optional path to save the double bumps to a file")
@click.pass_context
def check_version_lock(  # noqa: PLR0913
    ctx: click.Context,
    pr_number: int,
    local_file: str,
    token: str,
    comment: bool,
    save_double_bumps: Path,
) -> None:
    """
    Check the version lock file and optionally comment on the PR if the --comment flag is set.

    Note: Both --comment and --pr-number must be supplied for commenting to work.
    """
    if comment and not pr_number:
        raise click.UsageError("--comment requires --pr-number to be supplied.")

    github = GithubClient(token)
    github.assert_github()
    client = github.authenticated_client
    repo = client.get_repo("elastic/detection-rules")
    double_bumps = []
    comment_body = "No double bumps detected."

    def format_comment_body(double_bumps: list[tuple[str, str, int, int]]) -> str:
        """Format the comment body for double bumps."""
        comment_body = f"{len(double_bumps)} Double bumps detected:\n\n"
        comment_body += "<details>\n"
        comment_body += "<summary>Click to expand the list of double bumps</summary>\n\n"
        for rule_id, rule_name, removed, added in double_bumps:
            comment_body += f"- **Rule ID**: {rule_id}\n"
            comment_body += f"  - **Rule Name**: {rule_name}\n"
            comment_body += f"  - **Removed**: {removed}\n"
            comment_body += f"  - **Added**: {added}\n"
        comment_body += "\n</details>\n"
        return comment_body

    def save_double_bumps_to_file(double_bumps: list[tuple[str, str, int, int]], save_path: Path) -> None:
        """Save double bumps to a CSV file."""
        save_path.parent.mkdir(parents=True, exist_ok=True)
        if save_path.is_file():
            click.echo(f"File {save_path} already exists. Skipping save.")
        else:
            with save_path.open("w", newline="") as csvfile:
                csv.writer(csvfile).writerows([["Rule ID", "Rule Name", "Removed", "Added"], *double_bumps])
            click.echo(f"Double bumps saved to {save_path}")

    pr = None

    if pr_number:
        click.echo(f"Fetching version lock file from PR #{pr_number}")
        pr = repo.get_pull(pr_number)
        double_bumps = check_version_lock_double_bumps(
            repo=repo, file_path="detection_rules/etc/version.lock.json", base_branch="main", branch=pr.head.ref
        )
    else:
        click.echo(f"Using local version lock file: {local_file}")
        double_bumps = check_version_lock_double_bumps(repo=repo, file_path=local_file, base_branch="main")

    if double_bumps:
        click.echo(f"{len(double_bumps)} Double bumps detected")
        if comment and pr_number:
            comment_body = format_comment_body(double_bumps)
            if pr:
                _ = pr.create_issue_comment(comment_body)
        if save_double_bumps:
            save_double_bumps_to_file(double_bumps, save_double_bumps)
        ctx.exit(1)
    else:
        click.echo("No double bumps detected.")
        if comment and pr_number and pr:
            _ = pr.create_issue_comment(comment_body)


@dataclasses.dataclass
class GitChangeEntry:
    status: str
    original_path: Path
    new_path: Path | None = None

    @classmethod
    def from_line(cls, text: str) -> "GitChangeEntry":
        columns = text.split("\t")
        if len(columns) not in (2, 3):
            raise ValueError("Unexpected number of columns")
        paths = [Path(c) for c in columns[1:]]
        return cls(columns[0], *paths)

    @property
    def path(self) -> Path:
        return self.new_path or self.original_path

    def revert(self, dry_run: bool = False) -> None:
        """Run a git command to revert this change."""

        def git(*args: Any) -> None:
            command_line = ["git"] + [str(arg) for arg in args]
            click.echo(subprocess.list2cmdline(command_line))

            if not dry_run:
                _ = subprocess.check_call(command_line)

        if self.status.startswith("R"):
            # renames are actually Delete (D) and Add (A)
            # revert in opposite order
            if not self.new_path:
                raise ValueError("No new path found")
            GitChangeEntry("A", self.new_path).revert(dry_run=dry_run)
            GitChangeEntry("D", self.original_path).revert(dry_run=dry_run)
            return

        # remove the file from the staging area (A|M|D)
        git("restore", "--staged", self.original_path)

    def read(self, git_tree: str = "HEAD") -> bytes:
        """Read the file from disk or git."""
        if self.status == "D":
            # deleted files need to be recovered from git
            return subprocess.check_output(["git", "show", f"{git_tree}:{self.path}"])  # noqa: S607

        return self.path.read_bytes()


@dev_group.command("unstage-incompatible-rules")
@click.option("--target-stack-version", "-t", help="Minimum stack version to filter the staging area", required=True)
@click.option("--dry-run", is_flag=True, help="List the changes that would be made")
@click.option("--exception-list", help="List of files to skip staging", default="")
def prune_staging_area(target_stack_version: str, dry_run: bool, exception_list: str) -> None:
    """Prune the git staging area to remove changes to incompatible rules."""
    exceptions = {
        "detection_rules/etc/packages.yaml",
    }
    exceptions.update(exception_list.split(","))

    target_stack_version_parsed = Version.parse(target_stack_version, optional_minor_and_patch=True)

    # load a structured summary of the diff from git
    git_output = subprocess.check_output(["git", "diff", "--name-status", "HEAD"])  # noqa: S607
    changes = [GitChangeEntry.from_line(line) for line in git_output.decode("utf-8").splitlines()]

    # track which changes need to be reverted because of incompatibilities
    reversions: list[GitChangeEntry] = []

    for change in changes:
        if str(change.path) in exceptions:
            # Don't backport any changes to files matching the list of exceptions
            reversions.append(change)
            continue

        # it's a change to a rule file, load it and check the version
        for rules_dir in RULES_CONFIG.rule_dirs:
            if str(change.path.absolute()).startswith(str(rules_dir)) and change.path.suffix == ".toml":
                # bypass TOML validation in case there were schema changes
                dict_contents = RuleCollection.deserialize_toml_string(change.read())
                min_stack_version: str | None = dict_contents.get("metadata", {}).get("min_stack_version")

                if min_stack_version is not None and (
                    target_stack_version_parsed < Version.parse(min_stack_version, optional_minor_and_patch=True)
                ):
                    # rule is incompatible, add to the list of reversions to make later
                    reversions.append(change)
                break

    if len(reversions) == 0:
        click.echo("No files restored from staging area")
        return

    click.echo(f"Restoring {len(reversions)} changes from the staging area...")
    for change in reversions:
        change.revert(dry_run=dry_run)


@dev_group.command("update-lock-versions")
@click.argument("rule-ids", nargs=-1, required=False)
@click.pass_context
@click.option("--force", is_flag=True, help="Force update without confirmation")
def update_lock_versions(ctx: click.Context, rule_ids: tuple[str, ...], force: bool) -> list[definitions.UUIDString]:
    """Update rule hashes in version.lock.json file without bumping version."""
    rules = RuleCollection.default()
    rules = rules.filter(lambda r: r.id in rule_ids) if rule_ids else rules.filter(production_filter)

    if not force and not click.confirm(
        f"Are you sure you want to update hashes for {len(rules)} rules without a version bump?"
    ):
        return []

    if RULES_CONFIG.bypass_version_lock:
        click.echo(
            "WARNING: You cannot run this command when the versioning strategy is configured to bypass the "
            "version lock. Set `bypass_version_lock` to `False` in the rules config to use the version lock."
        )
        ctx.exit()

    # this command may not function as expected anymore due to previous changes eliminating the use of add_new=False
    changed, _, _ = loaded_version_lock.manage_versions(rules, exclude_version_update=True, save_changes=True)

    if not changed:
        click.echo("No hashes updated")

    return changed


@dev_group.command("kibana-diff")
@click.option("--rule-id", "-r", multiple=True, help="Optionally specify rule ID")
@click.option("--repo", default="elastic/kibana", help="Repository where branch is located")
@click.option("--branch", "-b", default="main", help="Specify the kibana branch to diff against")
@click.option("--threads", "-t", type=click.IntRange(1), default=50, help="Number of threads to use to download rules")
def kibana_diff(rule_id: list[str], repo: str, branch: str, threads: int) -> dict[str, Any]:
    """Diff rules against their version represented in kibana if exists."""
    from .misc import get_kibana_rules

    rules = RuleCollection.default()
    rules = rules.filter(lambda r: r.id in rule_id).id_map if rule_id else rules.filter(production_filter).id_map

    repo_hashes = {r.id: r.contents.get_hash(include_version=True) for r in rules.values()}

    kibana_rules = {r["rule_id"]: r for r in get_kibana_rules(repo=repo, branch=branch, threads=threads).values()}
    kibana_hashes = {r["rule_id"]: dict_hash(r) for r in kibana_rules.values()}

    missing_from_repo = list(set(kibana_hashes).difference(set(repo_hashes)))
    missing_from_kibana = list(set(repo_hashes).difference(set(kibana_hashes)))

    rule_diff: list[str] = []
    for _rule_id, _rule_hash in repo_hashes.items():
        if _rule_id in missing_from_kibana:
            continue
        if _rule_hash != kibana_hashes[_rule_id]:
            rule_diff.append(
                f"versions - repo: {rules[_rule_id].contents.autobumped_version}, "
                f"kibana: {kibana_rules[_rule_id]['version']} -> "
                f"{_rule_id} - {rules[_rule_id].contents.name}"
            )

    diff: dict[str, Any] = {
        "missing_from_kibana": [f"{r} - {rules[r].name}" for r in missing_from_kibana],
        "diff": rule_diff,
        "missing_from_repo": [f"{r} - {kibana_rules[r]['name']}" for r in missing_from_repo],
    }

    diff["stats"] = {k: len(v) for k, v in diff.items()}
    diff["stats"].update(total_repo_prod_rules=len(rules), total_gh_prod_rules=len(kibana_rules))

    click.echo(json.dumps(diff, indent=2, sort_keys=True))
    return diff


@dev_group.command("integrations-pr")
@click.argument(
    "local-repo",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    default=get_path(["..", "integrations"]),
)
@click.option(
    "--token",
    required=True,
    prompt=get_github_token() is None,
    default=get_github_token(),
    help="GitHub token to use for the PR",
    hide_input=True,
)
@click.option(
    "--pkg-directory",
    "-d",
    help="Directory to save the package in cloned repository",
    default=Path("packages", "security_detection_engine"),
)
@click.option("--base-branch", "-b", help="Base branch in target repository", default="main")
@click.option("--branch-name", "-n", help="New branch for the rules commit")
@click.option("--github-repo", "-r", help="Repository to use for the branch", default="elastic/integrations")
@click.option("--assign", multiple=True, help="GitHub users to assign the PR")
@click.option("--label", multiple=True, help="GitHub labels to add to the PR")
@click.option("--draft", is_flag=True, help="Open the PR as a draft")
@click.option("--remote", help="Override the remote from 'origin'", default="origin")
@click.pass_context
def integrations_pr(  # noqa: PLR0913, PLR0915
    ctx: click.Context,
    local_repo: Path,
    token: str,
    draft: bool,
    pkg_directory: str,
    base_branch: str,
    remote: str,
    branch_name: str | None,
    github_repo: str,
    assign: tuple[str, ...],
    label: tuple[str, ...],
) -> None:
    """Create a pull request to publish the Fleet package to elastic/integrations."""
    github = GithubClient(token)
    github.assert_github()
    client = github.authenticated_client
    repo = client.get_repo(github_repo)

    # Use elastic-package to format and lint
    gopath = utils.gopath()

    if not gopath:
        raise ValueError("GOPATH not found")

    gopath = gopath.strip("'\"")

    if not subprocess.check_output(["elastic-package"], stderr=subprocess.DEVNULL):  # noqa: S607
        raise ValueError(
            "elastic-package missing, run: go install github.com/elastic/elastic-package@latest and verify go bin path"
        )

    local_repo = Path(local_repo).resolve()
    stack_version = Package.load_configs()["name"]
    package_version = Package.load_configs()["registry_data"]["version"]

    release_dir = RELEASE_DIR / stack_version / "fleet" / package_version
    message = f"[Security Rules] Update security rules package to v{package_version}"

    if not release_dir.exists():
        click.secho("Release directory doesn't exist.", fg="red", err=True)
        click.echo(f"Run {click.style('python -m detection_rules dev build-release', bold=True)} to populate", err=True)
        ctx.exit(1)

    if not local_repo.exists():
        click.secho(f"{github_repo} is not present at {local_repo}.", fg="red", err=True)
        ctx.exit(1)

    # Get the most recent commit hash of detection-rules
    detection_rules_git = utils.make_git()
    long_commit_hash = detection_rules_git("rev-parse", "HEAD")
    short_commit_hash = detection_rules_git("rev-parse", "--short", "HEAD")

    # refresh the local clone of the repository
    git = utils.make_git("-C", local_repo)
    _ = git("checkout", base_branch)
    _ = git("pull", remote, base_branch)

    # Switch to a new branch in elastic/integrations
    branch_name = branch_name or f"detection-rules/{package_version}-{short_commit_hash}"
    _ = git("checkout", "-b", branch_name)

    # Load the changelog in memory, before it's removed. Come back for it after the PR is created
    target_directory = local_repo / pkg_directory
    changelog_path = target_directory / "changelog.yml"
    changelog_entries: list[dict[str, Any]] = yaml.safe_load(changelog_path.read_text(encoding="utf-8"))

    changelog_entries.insert(
        0,
        {
            "version": package_version,
            "changes": [
                # This will be changed later
                {
                    "description": "Release security rules update",
                    "type": "enhancement",
                    "link": "https://github.com/elastic/integrations/pulls/0000",
                }
            ],
        },
    )

    # Remove existing assets and replace everything
    shutil.rmtree(target_directory)
    actual_target_directory = shutil.copytree(release_dir, target_directory)
    if Path(actual_target_directory).absolute() != Path(target_directory).absolute():
        raise ValueError(f"Expected a copy to {pkg_directory}")

    # Add the changelog back
    def save_changelog() -> None:
        with changelog_path.open("wt") as f:
            # add a note for other maintainers of elastic/integrations to be careful with versions
            _ = f.write("# newer versions go on top\n")
            _ = f.write(
                "# NOTE: please use pre-release versions (e.g. -beta.0) until a package is ready for production\n"
            )
            yaml.dump(changelog_entries, f, allow_unicode=True, default_flow_style=False, indent=2, sort_keys=False)

    save_changelog()

    def elastic_pkg(*args: Any) -> None:
        """Run a command with $GOPATH/bin/elastic-package in the package directory."""
        prev = Path.cwd()
        os.chdir(target_directory)

        try:
            elastic_pkg_cmd = [str(Path(gopath, "bin", "elastic-package"))]
            elastic_pkg_cmd.extend(list(args))
            _ = subprocess.check_call(elastic_pkg_cmd)
        finally:
            os.chdir(str(prev))

    elastic_pkg("format")

    # Upload the files to a branch
    _ = git("add", pkg_directory)
    _ = git("commit", "-m", message)
    _ = git("push", "--set-upstream", remote, branch_name)

    # Create a pull request (not done yet, but we need the PR number)
    body = textwrap.dedent(f"""
    ## What does this PR do?
    Update the Security Rules package to version {package_version}.
    Autogenerated from commit  https://github.com/elastic/detection-rules/tree/{long_commit_hash}

    ## Checklist

    - [x] I have reviewed [tips for building integrations](https://github.com/elastic/integrations/blob/master/docs/tips_for_building_integrations.md) and this pull request is aligned with them.
    - [ ] ~I have verified that all data streams collect metrics or logs.~
    - [x] I have added an entry to my package's `changelog.yml` file.
    - [x] If I'm introducing a new feature, I have modified the Kibana version constraint in my package's `manifest.yml` file to point to the latest Elastic stack release (e.g. `^7.13.0`).

    ## Author's Checklist
    - Install the most recently release security rules in the Detection Engine
    - Install the package
    - Confirm the update is available in Kibana. Click "Update X rules" or "Install X rules"
    - Look at the changes made after the install and confirm they are consistent

    ## How to test this PR locally
    - Perform the above checklist, and use `package-storage` to build EPR from source

    ## Related issues
    None

    ## Screenshots
    None
    """)  # noqa: E501

    pr = repo.create_pull(
        title=message, body=body, base=base_branch, head=branch_name, maintainer_can_modify=True, draft=draft
    )

    # labels could also be comma separated
    cs_labels_split = {lbl for cs_labels in label for lbl in cs_labels.split(",") if lbl}

    labels = sorted(list(label) + list(cs_labels_split))

    if labels:
        pr.add_to_labels(*labels)

    if assign:
        pr.add_to_assignees(*assign)

    click.echo("PR created:")
    click.echo(pr.html_url)

    # replace the changelog entry with the actual PR link
    changelog_entries[0]["changes"][0]["link"] = pr.html_url
    save_changelog()

    # format the yml file with elastic-package
    _ = elastic_pkg("format")
    _ = elastic_pkg("lint")

    # Push the updated changelog to the PR branch
    _ = git("add", pkg_directory)
    _ = git("commit", "-m", f"Add changelog entry for {package_version}")
    _ = git("push")


@dev_group.command("license-check")
@click.option("--ignore-directory", "-i", multiple=True, help="Directories to skip (relative to base)")
@click.pass_context
def license_check(ctx: click.Context, ignore_directory: list[str]) -> None:
    """Check that all code files contain a valid license."""
    ignore_directory += ("env",)
    failed = False

    for path in utils.ROOT_DIR.rglob("*.py"):
        relative_path = path.relative_to(utils.ROOT_DIR)
        if relative_path.parts[0] in ignore_directory:
            continue

        with path.open(encoding="utf-8") as f:
            contents = f.read()

        # skip over shebang lines
        if contents.startswith("#!/"):
            _, _, contents = contents.partition("\n")

        if not contents.lstrip("\r\n").startswith(PYTHON_LICENSE):
            if not failed:
                click.echo("Missing license headers for:", err=True)

            failed = True
            click.echo(relative_path, err=True)

    ctx.exit(int(failed))


@dev_group.command("test-version-lock")
@click.argument("branches", nargs=-1, required=True)
@click.option("--remote", "-r", default="origin", help='Override the remote from "origin"')
@click.pass_context
def test_version_lock(ctx: click.Context, branches: list[str], remote: str) -> None:
    """Simulate the incremental step in the version locking to find version change violations."""
    git = utils.make_git("-C", ".")
    current_branch = git("rev-parse", "--abbrev-ref", "HEAD")

    try:
        click.echo(f"iterating lock process for branches: {branches}")
        for branch in branches:
            click.echo(branch)
            _ = git("checkout", f"{remote}/{branch}")
            _ = subprocess.check_call(["python", "-m", "detection_rules", "dev", "build-release", "-u"])  # noqa: S607

    finally:
        rules_config = ctx.obj["rules_config"]
        diff = git("--no-pager", "diff", str(rules_config.version_lock_file))
        outfile = utils.ROOT_DIR / "lock-diff.txt"
        _ = outfile.write_text(diff)
        click.echo(f"diff saved to {outfile}")

        click.echo("reverting changes in version.lock")
        _ = git("checkout", "-f")
        _ = git("checkout", current_branch)


@dev_group.command("package-stats")
@click.option("--token", "-t", help="GitHub token to search API authenticated (may exceed threshold without auth)")
@click.option("--threads", default=50, help="Number of threads to download rules from GitHub")
@click.pass_context
def package_stats(ctx: click.Context, token: str | None, threads: int) -> None:
    """Get statistics for current rule package."""
    current_package: Package = ctx.invoke(build_release, verbose=False)
    release = f"v{current_package.name}.0"
    new, modified, _ = rule_loader.load_github_pr_rules(labels=[release], token=token, threads=threads)

    click.echo(f"Total rules as of {release} package: {len(current_package.rules)}")
    click.echo(f"New rules: {len(current_package.new_ids)}")
    click.echo(f"Modified rules: {len(current_package.changed_ids)}")
    click.echo(f"Deprecated rules: {len(current_package.removed_ids)}")

    click.echo("\n-----\n")
    click.echo("Rules in active PRs for current package: ")
    click.echo(f"New rules: {len(new)}")
    click.echo(f"Modified rules: {len(modified)}")


@dev_group.command("search-rule-prs")
@click.argument("query", required=False)
@click.option("--no-loop", "-n", is_flag=True, help="Run once with no loop")
@click.option("--columns", "-c", multiple=True, help="Specify columns to add the table")
@click.option("--language", type=click.Choice(["eql", "kql"]), default="kql")
@click.option("--token", "-t", help="GitHub token to search API authenticated (may exceed threshold without auth)")
@click.option("--threads", default=50, help="Number of threads to download rules from GitHub")
@click.pass_context
def search_rule_prs(  # noqa: PLR0913
    ctx: click.Context,
    no_loop: bool,
    query: str | None,
    columns: list[str],
    language: Literal["eql", "kql"],
    token: str | None,
    threads: int,
) -> None:
    """Use KQL or EQL to find matching rules from active GitHub PRs."""
    from .main import search_rules

    all_rules: dict[Path, TOMLRule] = {}
    new, modified, _ = rule_loader.load_github_pr_rules(token=token, threads=threads)

    def add_github_meta(
        this_rule: TOMLRule,
        status: str,
        original_rule_id: definitions.UUIDString | None = None,
    ) -> None:
        pr = this_rule.gh_pr
        data = rule.contents.data
        extend_meta = {
            "status": status,
            "github": {
                "base": pr.base.label,
                "comments": [c.body for c in pr.get_comments()],
                "commits": pr.commits,
                "created_at": str(pr.created_at),
                "head": pr.head.label,
                "is_draft": pr.draft,
                "labels": [lbl.name for lbl in pr.get_labels()],
                "last_modified": str(pr.last_modified),
                "title": pr.title,
                "url": pr.html_url,
                "user": pr.user.login,
            },
        }

        if original_rule_id:
            extend_meta["original_rule_id"] = original_rule_id
            data = dataclasses.replace(rule.contents.data, rule_id=str(uuid4()))

        rule_path = Path(f"pr-{pr.number}-{rule.path}")
        new_meta = dataclasses.replace(rule.contents.metadata, extended=extend_meta)
        contents = dataclasses.replace(rule.contents, metadata=new_meta, data=data)
        new_rule = TOMLRule(path=rule_path, contents=contents)

        if not new_rule.path:
            raise ValueError("No rule path found")
        all_rules[new_rule.path] = new_rule

    for rule in new.values():
        add_github_meta(rule, "new")

    for rule_id, rules in modified.items():
        for rule in rules:
            add_github_meta(rule, "modified", rule_id)

    loop = not no_loop
    ctx.invoke(search_rules, query=query, columns=columns, language=language, rules=all_rules, pager=loop)

    while loop:
        query = click.prompt(f"Search loop - enter new {language} query or ctrl-z to exit")
        columns = click.prompt("columns", default=",".join(columns)).split(",")
        ctx.invoke(search_rules, query=query, columns=columns, language=language, rules=all_rules, pager=True)


@dev_group.command("deprecate-rule")
@click.argument("rule-file", type=Path)
@click.option(
    "--deprecation-folder", "-d", type=Path, required=True, help="Location to move the deprecated rule file to"
)
@click.pass_context
def deprecate_rule(ctx: click.Context, rule_file: Path, deprecation_folder: Path) -> None:
    """Deprecate a rule."""
    version_info = loaded_version_lock.version_lock
    rule_collection = RuleCollection()
    contents = rule_collection.load_file(rule_file).contents
    rule = TOMLRule(path=rule_file, contents=contents)  # type: ignore[reportArgumentType]

    if rule.contents.id not in version_info and not RULES_CONFIG.bypass_version_lock:
        click.echo(
            "Rule has not been version locked and so does not need to be deprecated. "
            "Delete the file or update the maturity to `development` instead."
        )
        ctx.exit()

    today = time.strftime("%Y/%m/%d")
    deprecated_path = deprecation_folder / rule_file.name

    # create the new rule and save it
    new_meta = dataclasses.replace(
        rule.contents.metadata, updated_date=today, deprecation_date=today, maturity="deprecated"
    )
    contents = dataclasses.replace(rule.contents, metadata=new_meta)
    new_rule = TOMLRule(contents=contents, path=deprecated_path)
    deprecated_path.parent.mkdir(parents=True, exist_ok=True)
    new_rule.save_toml()

    # remove the old rule
    rule_file.unlink()
    click.echo(f"Rule moved to {deprecated_path} - remember to git add this file")


@dev_group.command("update-navigator-gists")
@click.option(
    "--directory",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=True, path_type=Path),
    default=CURRENT_RELEASE_PATH.joinpath("extras", "navigator_layers"),
    help="Directory containing only navigator files.",
)
@click.option(
    "--token",
    required=True,
    prompt=get_github_token() is None,
    default=get_github_token(),
    help="GitHub token to push to gist",
    hide_input=True,
)
@click.option("--gist-id", default=NAVIGATOR_GIST_ID, help="Gist ID to be updated (must exist).")
@click.option("--print-markdown", is_flag=True, help="Print the generated urls")
@click.option("--update-coverage", is_flag=True, help=f"Update the {REPO_DOCS_DIR}/ATT&CK-coverage.md file")
def update_navigator_gists(
    directory: Path,
    token: str,
    gist_id: str,
    print_markdown: bool,
    update_coverage: bool,
) -> list[str]:
    """Update the gists with new navigator files."""

    def raw_permalink(raw_link: str) -> str:
        # Gist file URLs change with each revision, but can be permalinked to the latest by removing the hash after raw
        prefix, _, suffix = raw_link.rsplit("/", 2)
        return f"{prefix}/{suffix}"

    file_map = {f: f.read_text() for f in directory.glob("*.json")}
    try:
        response = update_gist(
            token, file_map, description="ATT&CK Navigator layer files.", gist_id=gist_id, pre_purge=True
        )
    except requests.exceptions.HTTPError as exc:
        if exc.response.status_code == requests.status_codes.codes.not_found:
            raise raise_client_error(
                "Gist not found: verify the gist_id exists and the token has access to it", exc=exc
            ) from exc
        if exc.response.status_code == requests.status_codes.codes.unauthorized:
            text = json.loads(exc.response.text).get(
                "message", "verify the token is valid and has the necessary permissions"
            )
            error_message = f"Unauthorized: {text}"
            raise raise_client_error(
                error_message,
                exc=exc,
            ) from exc
        raise

    response_data = response.json()
    raw_urls = {name: raw_permalink(data["raw_url"]) for name, data in response_data["files"].items()}

    base_url = "https://mitre-attack.github.io/attack-navigator/#layerURL={}&leave_site_dialog=false&tabs=false"

    # pull out full and platform coverage to print on top of markdown table
    all_url = base_url.format(urllib.parse.quote_plus(raw_urls.pop("Elastic-detection-rules-all.json")))
    platforms_url = base_url.format(urllib.parse.quote_plus(raw_urls.pop("Elastic-detection-rules-platforms.json")))

    generated_urls = [all_url, platforms_url]
    markdown_links: list[str] = []
    for name, gist_url in raw_urls.items():
        query = urllib.parse.quote_plus(gist_url)
        url = f"https://mitre-attack.github.io/attack-navigator/#layerURL={query}&leave_site_dialog=false&tabs=false"
        generated_urls.append(url)
        link_name = name.split(".")[0]
        markdown_links.append(f"|[{link_name}]({url})|")

    markdown = [
        f"**Full coverage**: {NAVIGATOR_BADGE}",
        "\n",
        f"**Coverage by platform**: [navigator]({platforms_url})",
        "\n",
        "| other navigator links by rule attributes |",
        "|------------------------------------------|",
        *markdown_links,
    ]

    if print_markdown:
        click.echo("\n".join(markdown) + "\n")

    if update_coverage:
        coverage_file_path = get_path([REPO_DOCS_DIR, "ATT&CK-coverage.md"])
        header_lines = textwrap.dedent("""# Rule coverage

ATT&CK navigator layer files are generated when a package is built with `make release` or
`python -m detection-rules`.This also means they can be downloaded from all successful builds.

These files can be used to pass to a custom navigator session. For convenience, the links are
generated below. You can also include multiple across tabs in a single session, though it is not
advisable to upload _all_ of them as it will likely overload your browsers resources.

## Current rule coverage

The source files for these links are regenerated with every successful merge to main. These represent
coverage from the state of rules in the `main` branch.
        """)
        updated_file = header_lines + "\n\n" + "\n".join(markdown) + "\n"
        # Replace the old URLs with the new ones
        with coverage_file_path.open("w") as md_file:
            _ = md_file.write(updated_file)
        click.echo(f"Updated ATT&CK coverage URL(s) in {coverage_file_path}" + "\n")

    click.echo(f"Gist update status on {len(generated_urls)} files: {response.status_code} {response.reason}")
    return generated_urls


@dev_group.command("trim-version-lock")
@click.argument("stack_version")
@click.option("--skip-rule-updates", is_flag=True, help="Skip updating the rules")
@click.option("--dry-run", is_flag=True, help="Print the changes rather than saving the file")
@click.pass_context
def trim_version_lock(  # noqa: PLR0912, PLR0915
    ctx: click.Context,
    stack_version: str,
    skip_rule_updates: bool,
    dry_run: bool,
) -> None:
    """Trim all previous entries within the version lock file which are lower than the min_version."""
    stack_versions = get_stack_versions()
    if stack_version not in stack_versions:
        raise ValueError(f"Unknown min_version ({stack_version}), expected: {', '.join(stack_versions)}")

    min_version = Version.parse(stack_version)

    if RULES_CONFIG.bypass_version_lock:
        click.echo(
            "WARNING: Cannot trim the version lock when the versioning strategy is configured to bypass the "
            "version lock. Set `bypass_version_lock` to `false` in the rules config to use the version lock."
        )
        ctx.exit()
    version_lock_dict = loaded_version_lock.version_lock.to_dict()
    removed: dict[str, list[str]] = defaultdict(list)
    rule_msv_drops: list[str] = []

    today = time.strftime("%Y/%m/%d")
    rc: RuleCollection | None = None
    if dry_run:
        rc = RuleCollection()
    elif not skip_rule_updates:
        click.echo("Loading rules ...")
        rc = RuleCollection.default()

    if not rc:
        raise ValueError("No rule collection found")

    for rule_id, lock in version_lock_dict.items():
        file_min_stack: Version | None = None
        if "min_stack_version" in lock:
            file_min_stack = Version.parse((lock["min_stack_version"]), optional_minor_and_patch=True)
            if file_min_stack <= min_version:
                removed[rule_id].append(
                    f"locked min_stack_version <= {min_version} - {'will remove' if dry_run else 'removing'}!"
                )
                rule_msv_drops.append(rule_id)
                file_min_stack = None

                if not dry_run:
                    lock.pop("min_stack_version")
                    if not skip_rule_updates:
                        # remove the min_stack_version and min_stack_comments from rules as well (and update date)
                        rule = rc.id_map.get(rule_id)
                        if rule:
                            new_meta = dataclasses.replace(
                                rule.contents.metadata,
                                updated_date=today,
                                min_stack_version=None,
                                min_stack_comments=None,
                            )
                            contents = dataclasses.replace(rule.contents, metadata=new_meta)
                            new_rule = TOMLRule(contents=contents, path=rule.path)
                            new_rule.save_toml()
                            removed[rule_id].append("rule min_stack_version dropped")
                        else:
                            removed[rule_id].append("rule not found to update!")

        if "previous" in lock:
            prev_vers = [Version.parse(v, optional_minor_and_patch=True) for v in list(lock["previous"])]
            outdated_vers = [v for v in prev_vers if v < min_version]

            if not outdated_vers:
                continue

            # we want to remove all "old" versions, but save the latest that is >= the min version supplied as the new
            # stack_version.
            latest_version = max(outdated_vers)

            for outdated in outdated_vers:
                short_outdated = f"{outdated.major}.{outdated.minor}"
                popped = lock["previous"].pop(str(short_outdated))
                # the core of the update - we only need to keep previous entries that are newer than the min supported
                # version (from stack-schema-map and stack-version parameter) and older than the locked
                # min_stack_version for a given rule, if one exists
                if file_min_stack and outdated == latest_version and outdated < file_min_stack:
                    lock["previous"][f"{min_version.major}.{min_version.minor}"] = popped
                    removed[rule_id].append(f"{short_outdated} updated to: {min_version.major}.{min_version.minor}")
                else:
                    removed[rule_id].append(f"{outdated} dropped")

            # remove the whole previous entry if it is now blank
            if not lock["previous"]:
                lock.pop("previous")

    click.echo(f"Changes {'that will be ' if dry_run else ''} applied:" if removed else "No changes")
    click.echo("\n".join(f"{k}: {', '.join(v)}" for k, v in removed.items()))
    if not dry_run:
        new_lock = VersionLockFile.from_dict({"data": version_lock_dict})
        new_lock.save_to_file()


@dev_group.group("diff")
def diff_group() -> None:
    """Commands for statistics on changes and diffs."""


@diff_group.command("endpoint-by-attack")
@click.option("--pre", required=True, help="Tag for pre-existing rules")
@click.option("--post", required=True, help="Tag for rules post updates")
@click.option("--force", "-f", is_flag=True, help="Bypass the confirmation prompt")
@click.option("--remote", "-r", default="origin", help='Override the remote from "origin"')
@click.pass_context
def endpoint_by_attack(
    ctx: click.Context,
    pre: str,
    post: str,
    force: bool,
    remote: str = "origin",
) -> tuple[Any, Any, Any]:
    """Rule diffs across tagged branches, broken down by ATT&CK tactics."""
    if not force and not click.confirm(
        f"This will refresh tags and may overwrite local tags for: {pre} and {post}. Continue?"
    ):
        ctx.exit(1)

    changed, new, deprecated = get_release_diff(pre, post, remote)
    oses = ("windows", "linux", "macos")

    def delta_stats(rule_map: dict[str, TOMLRule] | dict[str, DeprecatedRule]) -> list[dict[str, Any]]:
        stats: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        os_totals: dict[str, int] = defaultdict(int)
        tactic_totals: dict[str, int] = defaultdict(int)

        for rule in rule_map.values():
            threat = rule.contents.data.get("threat")
            os_types: list[str] = [i.lower() for i in rule.contents.data.get("tags") or [] if i.lower() in oses]  # type: ignore[reportUnknownVariableType]
            if not threat or not os_types:
                continue

            if isinstance(threat[0], dict):
                tactics = sorted({e["tactic"]["name"] for e in threat})
            else:
                tactics = ThreatMapping.flatten(threat).tactic_names
            for tactic in tactics:
                tactic_totals[tactic] += 1
                for os_type in os_types:
                    os_totals[os_type] += 1
                    stats[tactic][os_type] += 1

        # structure stats for table
        rows: list[dict[str, Any]] = []
        for tac, stat in stats.items():
            row: dict[str, Any] = {"tactic": tac, "total": tactic_totals[tac]}
            for os_type, count in stat.items():
                row[os_type] = count  # noqa: PERF403
            rows.append(row)

        rows.append(dict(tactic="total_by_os", **os_totals))
        return rows

    fields = ["tactic", "linux", "macos", "windows", "total"]

    changed_stats = delta_stats(changed)
    table = Table.from_list(fields, changed_stats)  # type: ignore[reportUnknownMemberType]
    click.echo(f"Changed rules {len(changed)}\n{table}\n")

    new_stats = delta_stats(new)
    table = Table.from_list(fields, new_stats)  # type: ignore[reportUnknownMemberType]
    click.echo(f"New rules {len(new)}\n{table}\n")

    dep_stats = delta_stats(deprecated)
    table = Table.from_list(fields, dep_stats)  # type: ignore[reportUnknownMemberType]
    click.echo(f"Deprecated rules {len(deprecated)}\n{table}\n")

    return changed_stats, new_stats, dep_stats


@dev_group.group("test")
def test_group() -> None:
    """Commands for testing against stack resources."""


@test_group.command("event-search")
@click.argument("query")
@click.option("--index", "-i", multiple=True, help="Index patterns to search against")
@click.option("--eql/--lucene", "-e/-l", "language", default=None, help="Query language used (default: kql)")
@click.option("--date-range", "-d", type=(str, str), default=("now-7d", "now"), help="Date range to scope search")
@click.option("--count", "-c", is_flag=True, help="Return count of results only")
@click.option(
    "--max-results",
    "-m",
    type=click.IntRange(1, 1000),
    default=100,
    help="Max results to return (capped at 1000)",
)
@click.option("--verbose", "-v", is_flag=True, default=True)
@add_client(["elasticsearch"])
def event_search(  # noqa: PLR0913
    query: str,
    index: list[str],
    language: str | None,
    date_range: tuple[str, str],
    count: bool,
    max_results: int,
    elasticsearch_client: Elasticsearch,
    verbose: bool = True,
) -> Any | list[Any]:
    """Search using a query against an Elasticsearch instance."""
    start_time, end_time = date_range
    index = index or ["*"]
    language_used = "kql" if language is None else "eql" if language else "lucene"
    collector = CollectEvents(elasticsearch_client, max_results)

    if verbose:
        click.echo(f"searching {','.join(index)} from {start_time} to {end_time}")
        click.echo(f"{language_used}: {query}")

    if count:
        results = collector.count(query, language_used, index, start_time, end_time)
        click.echo(f"total results: {results}")
    else:
        results = collector.search(query, language_used, index, start_time, end_time, max_results)
        click.echo(f"total results: {len(results)} (capped at {max_results})")
        click.echo_via_pager(json.dumps(results, indent=2, sort_keys=True))

    return results


@test_group.command("rule-event-search")
@single_collection
@click.option("--date-range", "-d", type=(str, str), default=("now-7d", "now"), help="Date range to scope search")
@click.option("--count", "-c", is_flag=True, help="Return count of results only")
@click.option(
    "--max-results",
    "-m",
    type=click.IntRange(1, 1000),
    default=100,
    help="Max results to return (capped at 1000)",
)
@click.option("--verbose", "-v", is_flag=True)
@click.pass_context
@add_client(["elasticsearch"])
def rule_event_search(  # noqa: PLR0913
    ctx: click.Context,
    rule: Any,
    date_range: tuple[str, str],
    count: bool,
    max_results: int,
    elasticsearch_client: Elasticsearch,
    verbose: bool = False,
) -> None:
    """Search using a rule file against an Elasticsearch instance."""

    if isinstance(rule.contents.data, QueryRuleData):
        if verbose:
            click.echo(f"Searching rule: {rule.name}")

        data = rule.contents.data
        rule_lang = data.language

        if rule_lang == "kuery":
            language_flag = None
        elif rule_lang == "eql":
            language_flag = True
        else:
            language_flag = False

        index = data.index or ["*"]
        ctx.invoke(
            event_search,
            query=data.query,
            index=index,
            language=language_flag,
            date_range=date_range,
            count=count,
            max_results=max_results,
            verbose=verbose,
            elasticsearch_client=elasticsearch_client,
        )
    else:
        raise_client_error("Rule is not a query rule!")


@test_group.command("esql-remote-validation")
@click.option(
    "--verbosity",
    type=click.IntRange(0, 1),
    default=0,
    help="Set verbosity level: 0 for minimal output, 1 for detailed output.",
)
def esql_remote_validation(
    verbosity: int,
) -> None:
    """Search using a rule file against an Elasticsearch instance."""

    rule_collection: RuleCollection = RuleCollection.default().filter(production_filter)
    esql_rules = [r for r in rule_collection if r.contents.data.type == "esql"]

    click.echo(f"ESQL rules loaded: {len(esql_rules)}")

    if not esql_rules:
        return
    # TODO(eric-forte-elastic): @add_client https://github.com/elastic/detection-rules/issues/5156  # noqa: FIX002
    with get_default_kibana_client() as kibana_client, get_default_elasticsearch_client() as elastic_client:
        if not kibana_client or not elastic_client:
            raise_client_error("Skipping remote validation due to missing client")

        failed_count = 0
        fail_list: list[str] = []
        max_retries = 3
        for r in esql_rules:
            retry_count = 0
            while retry_count < max_retries:
                try:
                    validator = ESQLValidator(r.contents.data.query)  # type: ignore[reportIncompatibleMethodOverride]
                    _ = validator.remote_validate_rule_contents(kibana_client, elastic_client, r.contents, verbosity)
                    break
                except (ValueError, BadRequestError, *ESQL_EXCEPTION_TYPES) as e:  # type: ignore[reportUnknownMemberType]
                    e_type = type(e)  # type: ignore[reportUnknownMemberType]
                    if isinstance(e, ESQL_EXCEPTION_TYPES):
                        click.echo(click.style(f"{r.contents.data.rule_id} ", fg="red", bold=True), nl=False)
                        _ = e.show()  # type: ignore[reportUnknownMemberType]
                    else:
                        click.echo(f"FAILURE: {e_type}: {e}")  # type: ignore[reportUnknownMemberType]
                    fail_list.append(f"{r.contents.data.rule_id}  FAILURE: {e_type}: {e}")  # type: ignore[reportUnknownMemberType]
                    failed_count += 1
                    break
                except ESConnectionError as e:
                    retry_count += 1
                    click.echo(f"Connection error: {e}. Retrying {retry_count}/{max_retries}...")
                    time.sleep(30)
                    if retry_count == max_retries:
                        click.echo(f"FAILURE: {e} after {max_retries} retries")
                        fail_list.append(f"FAILURE: {e} after {max_retries} retries")
                        failed_count += 1

        click.echo(f"Total rules: {len(esql_rules)}")
        click.echo(f"Failed rules: {failed_count}")

        _ = Path("failed_rules.log").write_text("\n".join(fail_list), encoding="utf-8")
        click.echo("Failed rules written to failed_rules.log")
        if failed_count > 0:
            click.echo("Failed rule IDs:")
            uuids = {line.split()[0] for line in fail_list}
            click.echo("\n".join(uuids))
            ctx = click.get_current_context()
            ctx.exit(1)


@test_group.command("rule-survey")
@click.argument("query", required=False)
@click.option("--date-range", "-d", type=(str, str), default=("now-7d", "now"), help="Date range to scope search")
@click.option(
    "--dump-file",
    type=click.Path(dir_okay=False, path_type=Path),
    default=get_path(["surveys", f"{time.strftime('%Y%m%dT%H%M%SL')}.json"]),
    help="Save details of results (capped at 1000 results/rule)",
)
@click.option("--hide-zero-counts", "-z", is_flag=True, help="Exclude rules with zero hits from printing")
@click.option("--hide-errors", "-e", is_flag=True, help="Exclude rules with errors from printing")
@click.pass_context
@add_client(["elasticsearch", "kibana"], add_to_ctx=True)
def rule_survey(  # noqa: PLR0913
    ctx: click.Context,
    query: str,
    date_range: tuple[str, str],
    dump_file: Path,
    hide_zero_counts: bool,
    hide_errors: bool,
    elasticsearch_client: Elasticsearch,
    kibana_client: Kibana,
) -> list[dict[str, int]]:
    """Survey rule counts."""

    from .main import search_rules

    survey_results: list[dict[str, int]] = []
    start_time, end_time = date_range

    if query:
        rules = RuleCollection()
        paths = [Path(r["file"]) for r in ctx.invoke(search_rules, query=query, verbose=False)]
        rules.load_files(paths)
    else:
        rules = RuleCollection.default().filter(production_filter)

    click.echo(f"Running survey against {len(rules)} rules")
    click.echo(f"Saving detailed dump to: {dump_file}")

    collector = CollectEvents(elasticsearch_client)
    details = collector.search_from_rule(rules, start_time=start_time, end_time=end_time)
    counts = collector.count_from_rule(rules, start_time=start_time, end_time=end_time)

    # add alerts
    with kibana_client:
        range_dsl: dict[str, Any] = {"query": {"bool": {"filter": []}}}
        add_range_to_dsl(range_dsl["query"]["bool"]["filter"], start_time, end_time)
        alerts: dict[str, Any] = {
            a["_source"]["signal"]["rule"]["rule_id"]: a["_source"]
            for a in Signal.search(range_dsl, size=10000)["hits"]["hits"]  # type: ignore[reportUnknownMemberType]
        }

    for rule_id, count in counts.items():
        alert_count = len(alerts.get(rule_id, []))
        if alert_count > 0:
            count["alert_count"] = alert_count

        details[rule_id].update(count)

        search_count = count["search_count"]
        if (not alert_count and (hide_zero_counts and search_count == 0)) or (hide_errors and search_count == -1):
            continue

        survey_results.append(count)

    fields = ["rule_id", "name", "search_count", "alert_count"]
    table = Table.from_list(fields, survey_results)  # type: ignore[reportUnknownMemberType]

    if len(survey_results) > 200:  # noqa: PLR2004
        click.echo_via_pager(table)
    else:
        click.echo(table)

    get_path(["surveys"]).mkdir(exist_ok=True)
    with dump_file.open("w") as f:
        json.dump(details, f, indent=2, sort_keys=True)

    return survey_results


@dev_group.group("utils")
def utils_group() -> None:
    """Commands for dev utility methods."""


@utils_group.command("get-branches")
@click.option(
    "--outfile",
    "-o",
    type=Path,
    default=get_etc_path(["target-branches.yaml"]),
    help="File to save output to",
)
def get_branches(outfile: Path) -> None:
    branch_list = get_stack_versions(drop_patch=True)
    target_branches = json.dumps(branch_list[:-1]) + "\n"
    _ = outfile.write_text(target_branches)


@dev_group.group("integrations")
def integrations_group() -> None:
    """Commands for dev integrations methods."""


@integrations_group.command("build-manifests")
@click.option("--overwrite", "-o", is_flag=True, help="Overwrite the existing integrations-manifest.json.gz file")
@click.option("--integration", "-i", type=str, help="Adds an integration tag to the manifest file")
@click.option("--prerelease", "-p", is_flag=True, default=False, help="Include prerelease versions")
def build_integration_manifests(overwrite: bool, integration: str, prerelease: bool = False) -> None:
    """Builds consolidated integrations manifests file."""
    click.echo("loading rules to determine all integration tags")

    def flatten(tag_list: list[str | list[str]] | list[str]) -> list[str]:
        return list({tag for tags in tag_list for tag in (flatten(tags) if isinstance(tags, list) else [tags])})

    if integration:
        build_integrations_manifest(overwrite=False, integration=integration, prerelease=prerelease)
    else:
        rules = RuleCollection.default()
        integration_tags = [r.contents.metadata.integration for r in rules if r.contents.metadata.integration]
        unique_integration_tags = flatten(integration_tags)
        click.echo(f"integration tags identified: {unique_integration_tags}")
        build_integrations_manifest(overwrite, rule_integrations=unique_integration_tags)


@integrations_group.command("build-schemas")
@click.option("--overwrite", "-o", is_flag=True, help="Overwrite the entire integrations-schema.json.gz file")
@click.option(
    "--integration", "-i", type=str, help="Adds a single integration schema to the integrations-schema.json.gz file"
)
def build_integration_schemas(overwrite: bool, integration: str) -> None:
    """Builds consolidated integrations schemas file."""
    click.echo("Building integration schemas...")

    start_time = time.perf_counter()
    if integration:
        build_integrations_schemas(overwrite=False, integration=integration)
    else:
        build_integrations_schemas(overwrite=overwrite)
        end_time = time.perf_counter()
        click.echo(f"Time taken to generate schemas: {(end_time - start_time) / 60:.2f} minutes")


@integrations_group.command("show-latest-compatible")
@click.option("--package", "-p", help="Name of package")
@click.option("--stack_version", "-s", required=True, help="Rule stack version")
def show_latest_compatible_version(package: str, stack_version: str) -> None:
    """Prints the latest integration compatible version for specified package based on stack version supplied."""

    packages_manifest = None
    try:
        packages_manifest = load_integrations_manifests()
    except Exception as e:  # noqa: BLE001
        click.echo(f"Error loading integrations manifests: {e!s}")
        return

    try:
        version = find_latest_compatible_version(
            package, "", Version.parse(stack_version, optional_minor_and_patch=True), packages_manifest
        )
        click.echo(f"Compatible integration {version=}")
    except Exception as e:  # noqa: BLE001
        click.echo(f"Error finding compatible version: {e!s}")
        return


@dev_group.group("schemas")
def schemas_group() -> None:
    """Commands for dev schema methods."""


@schemas_group.command("update-rule-data")
def update_rule_data_schemas() -> None:
    classes = [BaseRuleData, *typing.get_args(AnyRuleData)]

    for cls in classes:
        _ = cls.save_schema()


@schemas_group.command("generate")
@click.option(
    "--token",
    required=True,
    prompt=get_github_token() is None,
    default=get_github_token(),
    help="GitHub token to use for the PR",
    hide_input=True,
)
@click.option(
    "--schema",
    "-s",
    required=True,
    type=click.Choice(["endgame", "ecs", "beats", "endpoint"]),
    help="Schema to generate",
)
@click.option("--schema-version", "-sv", help="Tagged version from TBD. e.g., 1.9.0")
@click.option("--endpoint-target", "-t", type=str, default="endpoint", help="Target endpoint schema")
@click.option("--overwrite", is_flag=True, help="Overwrite if versions exist")
def generate_schema(token: str, schema: str, schema_version: str, endpoint_target: str, overwrite: bool) -> None:
    """Download schemas and generate flattend schema."""
    github = GithubClient(token)
    client = github.authenticated_client

    if schema_version and not Version.parse(schema_version):
        raise click.BadParameter(f"Invalid schema version: {schema_version}")

    click.echo(f"Generating {schema} schema")
    if schema == "endgame":
        if not schema_version:
            raise click.BadParameter("Schema version required")
        schema_manager = EndgameSchemaManager(client, schema_version)
        schema_manager.save_schemas(overwrite=overwrite)

    # ecs, beats and endpoint schemas are refreshed during release
    # these schemas do not require a schema version
    if schema == "ecs":
        download_schemas(refresh_all=True)
    if schema == "beats":
        if not schema_version:
            download_latest_beats_schema()
            refresh_main_schema()
        else:
            download_beats_schema(schema_version)

    # endpoint package custom schemas can be downloaded
    # this download requires a specific schema target
    if schema == "endpoint":
        repo = client.get_repo("elastic/endpoint-package")
        contents = repo.get_contents("custom_schemas")
        optional_endpoint_targets = [
            Path(f.path).name.replace("custom_", "").replace(".yml", "")  # type: ignore[reportUnknownMemberType]
            for f in contents  # type: ignore[reportUnknownVariableType]
            if f.name.endswith(".yml") or Path(f.path).name == endpoint_target  # type: ignore[reportUnknownMemberType]
        ]

        if not endpoint_target:
            raise click.BadParameter("Endpoint target required")
        if endpoint_target not in optional_endpoint_targets:
            raise click.BadParameter(f"""Invalid endpoint schema target: {endpoint_target}
                                      \n Schema Options: {optional_endpoint_targets}""")
        download_endpoint_schemas(endpoint_target)
    click.echo(f"Done generating {schema} schema")


@dev_group.group("attack")
def attack_group() -> None:
    """Commands for managing Mitre ATT&CK data and mappings."""


@attack_group.command("refresh-data")
def refresh_attack_data() -> dict[str, Any] | None:
    """Refresh the ATT&CK data file."""
    data, _ = attack.refresh_attack_data()
    return data


@attack_group.command("refresh-redirect-mappings")
def refresh_threat_mappings() -> None:
    """Refresh the ATT&CK redirect file and update all rule threat mappings."""
    # refresh the attack_technique_redirects
    click.echo("refreshing data in attack_technique_redirects.json")
    attack.refresh_redirected_techniques_map()


def _threat_entry_technique_flat(entry: ThreatMapping) -> tuple[list[str], list[str]]:
    """Collect technique and sub-technique IDs and display names from one ``ThreatMapping`` row.

    Order matches traversal of ``entry.technique`` and nested ``subtechnique`` lists. Used when
    deciding whether redirects or MITRE ATT&CK data name drift require rebuilding that row.
    """
    technique_ids: list[str] = []
    technique_names: list[str] = []
    for technique in entry.technique or []:
        technique_ids.append(technique.id)
        technique_names.append(technique.name)
        if technique.subtechnique:
            for st in technique.subtechnique:
                technique_ids.append(st.id)
                technique_names.append(st.name)
    return technique_ids, technique_names


def _legacy_technique_name_drift(technique_ids: list[str], technique_names: list[str]) -> bool:
    """Return True if any stored technique *name* no longer matches the bundled MITRE ATT&CK data name.

    Mirrors historical ``update-rules`` logic: compares each non-empty ``technique_names`` entry to
    ``technique_lookup[tid]['name']`` for IDs present in the lookup table.
    """
    return any(
        tname
        for tname in technique_names
        if tname
        not in [
            attack.technique_lookup[str(tid)]["name"]
            for tid in technique_ids
            if str(tid) in attack.technique_lookup
        ]
    )


def _mitre_threat_persist_sort_key(entry: ThreatMapping) -> tuple[int, str, str]:
    """Save order for ``rule.threat`` rows (migrate / update-rules).

    Primary sort: ``attack.priority_mitre_tactic_display_names_from_migration_hints``; then tactic name.
    """
    if entry.framework == "MITRE ATLAS":
        return (10_000, entry.tactic.name, entry.tactic.id)
    if entry.framework != "MITRE ATT&CK":
        return (20_000, entry.tactic.name, entry.tactic.id)
    priority = attack.priority_mitre_tactic_display_names_from_migration_hints()
    if entry.tactic.name in priority:
        return (priority.index(entry.tactic.name), entry.tactic.name, entry.tactic.id)
    base = len(priority)
    return (base, entry.tactic.name, entry.tactic.id)


def _normalized_threat_signature(th: list[ThreatMapping] | None) -> tuple[Any, ...]:
    """Build a comparable snapshot of MITRE threat rows (tactic + technique id sets).

    Entries are sorted by ``(tactic.name, tactic.id)`` so order alone does not force a save.
    Used by ``update-rules`` to skip writes when rebuilt threat metadata is equivalent.
    """
    if not th:
        return ()
    flat: list[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = []
    for entry in sorted(th, key=lambda x: (x.tactic.name, x.tactic.id)):
        f = ThreatMapping.flatten([entry])
        flat.append(
            (
                entry.tactic.name,
                entry.tactic.id,
                tuple(sorted(f.technique_ids)),
                tuple(sorted(f.sub_technique_ids)),
            )
        )
    return tuple(flat)


def path_for_rule_file_name_tactic(
    current: Path,
    threat: list[ThreatMapping] | None,
    authors: list[str],
    rule_type: str,
) -> Path:
    """Return the filesystem path the rule file should use under ``test_rule_file_name_tactic``.

    **Gates (same as the unit test):** skip ML rules; skip when there is no threat or ``Elastic`` is
    not in ``authors``. Otherwise the basename must begin with the slug for ``threat[0].tactic``
    (lower snake-case). ``threat`` should be sorted with ``_mitre_threat_persist_sort_key`` when produced
    by migrate so ``threat[0]`` reflects TA0005 successor priority from migration hints.

    **Rename strategy:** only when the stem matches a legacy prefix from
    ``definitions.ATTACK_TACTIC_MIGRATION_FILENAME_LEGACY_STEM_PREFIXES`` (e.g. ``defense_evasion_``).
    Replace that prefix with ``threat[0]`` slug. Otherwise leave the path unchanged.

    **Returns:** ``current`` or a same-directory path with a new basename (``.toml`` preserved).
    """
    if rule_type == definitions.MACHINE_LEARNING:
        return current
    if not threat or "Elastic" not in authors:
        return current
    slug = threat[0].tactic.name.lower().replace(" ", "_")
    filename = current.name
    if len(filename) >= len(slug) and filename[: len(slug)] == slug:
        return current
    stem = current.stem
    for legacy_prefix in sorted(attack.filename_legacy_stem_prefixes(), key=len, reverse=True):
        if stem.startswith(legacy_prefix):
            remainder = stem[len(legacy_prefix) :]
            new_stem = f"{slug}_{remainder}" if remainder else slug
            return current.with_name(new_stem + ".toml")
    return current


def remap_entries_with_unknown_mitre_tactics(
    threat: list[ThreatMapping],
    rule_label: str = "",
) -> tuple[list[ThreatMapping], bool, set[str], list[tuple[str, list[str]]]]:
    """Rewrite MITRE ATT&CK rows whose ``tactic.name`` is missing from bundled MITRE ATT&CK data.

    **Preserves:** non-MITRE frameworks and MITRE rows whose tactic exists in ``attack.tactics_map``.
    **Rewrites:** unknown ``tactic.name`` rows. If ``tactic.id`` is still a valid external id
    (e.g. ``TA0005``) and every technique still appears under that id's current display name in
    the matrix, the row is rebuilt with that name only (Defense Evasion → Stealth). Otherwise
    ``attack.rebuild_threat_dicts_from_technique_ids`` infers from technique IDs. One input row
    may become several rows if techniques truly span tactics.

    **Returns:**
      - New threat list sorted for persistence (see ``_mitre_threat_persist_sort_key``).
      - Whether any row changed.
      - Display names of tactics introduced by rebuilt rows (for ``replace_retired_tactic_tags``).
      - **remap_log:** one ``(old_tactic_name, [new_tactic_names])`` per rewritten unknown row.

    **Unknown tactic + no techniques:** if ``tactic.id`` maps to a current bundle tactic (via
    ``attack.tactic_id_to_name``), write a tactic-only row using that display name. Otherwise
    ``ValueError``.

    **rule_label:** optional ``name (uuid)`` string for error messages.
    """
    new_list: list[ThreatMapping] = []
    changed = False
    replacement_tactic_names: set[str] = set()
    remap_log: list[tuple[str, list[str]]] = []
    for entry in threat:
        if entry.framework != "MITRE ATT&CK" or entry.tactic.name in attack.tactics_map:
            new_list.append(entry)
            continue
        old_tactic = entry.tactic.name
        technique_ids, _ = _threat_entry_technique_flat(entry)
        if not technique_ids:
            fb = attack.tactic_id_to_name.get(entry.tactic.id)
            if not fb:
                prefix = f"{rule_label}: " if rule_label else ""
                raise ValueError(
                    f"{prefix}MITRE tactic {old_tactic!r} (id {entry.tactic.id!r}) is unknown to bundled "
                    "ATT&CK data and no techniques were listed (cannot infer). Fix TOML or use techniques "
                    "under this row."
                )
            rebuilt_empty = attack.build_threat_map_entry(fb)
            remap_log.append((old_tactic, [fb]))
            replacement_tactic_names.add(fb)
            new_list.append(ThreatMapping.from_dict(rebuilt_empty))
            changed = True
            continue
        retained = attack.retain_tactic_display_if_id_and_techniques_still_match(entry.tactic.id, technique_ids)
        if retained is not None:
            sorted_ids = sorted(set(technique_ids), key=lambda x: (x.split(".")[0], x))
            rebuilt_retained = attack.build_threat_map_entry(retained, *sorted_ids)
            remap_log.append((old_tactic, [retained]))
            replacement_tactic_names.add(retained)
            new_list.append(ThreatMapping.from_dict(rebuilt_retained))
            changed = True
            continue
        row_tid = entry.tactic.id if entry.tactic.id in attack.tactic_id_to_name else None
        rebuilt = attack.rebuild_threat_dicts_from_technique_ids(technique_ids, row_tactic_external_id=row_tid)
        new_names = sorted({r["tactic"]["name"] for r in rebuilt})
        remap_log.append((old_tactic, new_names))
        for r in rebuilt:
            replacement_tactic_names.add(r["tactic"]["name"])
            new_list.append(ThreatMapping.from_dict(r))
        changed = True
    new_list.sort(key=_mitre_threat_persist_sort_key)
    return new_list, changed, replacement_tactic_names, remap_log


def replace_retired_tactic_tags(
    tags: list[str],
    new_mitre_tactic_names: set[str],
    *,
    retired_tactic_display_names: set[str],
) -> tuple[list[str], bool]:
    """Align ``tags`` with tactics produced by ``remap_entries_with_unknown_mitre_tactics``.

    Drops ``Tactic: {name}`` for each ``retired_tactic_display_names`` entry (stale display names
    from remapped rows). Appends ``Tactic: {name}`` for each name in ``new_mitre_tactic_names``
    (sorted) when missing.

    **Returns:** updated tag list and whether any tag string changed.
    """
    strip_tags = {f"Tactic: {n}" for n in retired_tactic_display_names}
    out = [t for t in tags if t not in strip_tags]
    tag_changed = len(out) != len(tags)
    for name in sorted(new_mitre_tactic_names):
        t = f"Tactic: {name}"
        if t not in out:
            out.append(t)
            tag_changed = True
    return out, tag_changed


@attack_group.command("migrate-retired-tactics")
@click.option("--dry-run", is_flag=True, help="Print rules that would change without writing TOML.")
def migrate_retired_mitre_tactics(dry_run: bool) -> list[TOMLRule]:
    """Bulk-fix rules whose MITRE tactic labels are absent from the current ATT&CK bundle.

    Run after replacing ``attack-v*.json.gz`` when enterprise tactic names change (e.g. Defense
    Evasion retired). For each production rule:

    - Rebuild unknown MITRE tactic rows from technique IDs (see ``remap_entries_with_unknown_mitre_tactics``).
    - Refresh tags: remove ``Tactic: …`` for each remapped old tactic name; add tactic tags for new rows.
    - Rename files only when the stem matches ``ATTACK_TACTIC_MIGRATION_FILENAME_LEGACY_STEM_PREFIXES``
      (``path_for_rule_file_name_tactic``); swap to ``threat[0]`` slug.

    **``--dry-run``:** print rule names, **tactic remaps** (e.g. Defense Evasion -> Stealth), planned
    file renames, then exit without writing files.

    **Side effects:** sets ``metadata.updated_date`` to today on save; deletes the old file path
    when the basename changes. Refuses to overwrite an existing target path.

    **Returns:** rules written (or counted in dry-run); empty list if nothing needed migration.
    """
    today = time.strftime("%Y/%m/%d")
    rules = RuleCollection.default()
    updated: list[TOMLRule] = []

    for rule in rules.rules:
        threat = rule.contents.data.threat or []
        new_threat, changed, replacement_names, remap_log = remap_entries_with_unknown_mitre_tactics(
            threat, rule_label=f"{rule.contents.name} ({rule.id})"
        )
        if not changed:
            continue
        click.echo(f"{'[dry-run] ' if dry_run else ''}{rule.contents.name} ({rule.id})")
        for old_tactic, new_names in remap_log:
            click.echo(f"  tactics: {old_tactic} -> {', '.join(new_names)}")
        retired_names = {old for old, _ in remap_log}
        new_tags, _ = replace_retired_tactic_tags(
            list(rule.contents.data.tags or []),
            replacement_names,
            retired_tactic_display_names=retired_names,
        )
        target_path = path_for_rule_file_name_tactic(
            rule.path, new_threat, rule.contents.data.author, rule.contents.data.type
        )
        if target_path.resolve() != rule.path.resolve():
            click.echo(f"  {'would rename' if dry_run else 'rename'}: {rule.path.name} -> {target_path.name}")
        if dry_run:
            updated.append(rule)
            continue
        if target_path.exists() and target_path.resolve() != rule.path.resolve():
            raise FileExistsError(f"Refusing to overwrite existing file: {target_path}")
        new_meta = dataclasses.replace(rule.contents.metadata, updated_date=today)
        new_data = dataclasses.replace(rule.contents.data, threat=new_threat, tags=new_tags)
        new_contents = dataclasses.replace(rule.contents, data=new_data, metadata=new_meta)
        new_rule = TOMLRule(contents=new_contents, path=target_path)
        new_rule.save_toml()
        if target_path.resolve() != rule.path.resolve() and rule.path.exists():
            rule.path.unlink()
        updated.append(new_rule)

    if dry_run:
        click.echo(f"\nDry-run: {len(updated)} rule(s) would be updated.")
    elif updated:
        click.echo(f"\nFinished — {len(updated)} rule(s) updated.")
    else:
        click.echo("No rule changes needed.")
    return updated


@attack_group.command("update-rules")
def update_attack_in_rules() -> list[TOMLRule]:  # noqa: PLR0912, PLR0915
    """Refresh MITRE technique IDs, names, and tactics across all default rules.

    For each ``[[rule.threat]]`` entry:

    - **Atlas / non-MITRE:** copied unchanged.
    - **MITRE + tactic unknown to MITRE ATT&CK data:** rebuilt from technique IDs via
      ``attack.rebuild_threat_dicts_from_technique_ids`` (same inference as migrate).
    - **MITRE + known tactic:** rebuilt when technique IDs hit ``attack-technique-redirects`` or
      technique display names drift from ``technique_lookup``; otherwise left as-is.

    Sorts threat rows by tactic name. Updates ``metadata.updated_date`` only when the normalized
    threat signature changes. Does **not** rename files or edit tactic tags (use
    ``migrate-retired-tactics`` for retired tactic labels and filenames).

    **Returns:** list of rules that were saved.
    """
    new_rules: list[TOMLRule] = []
    redirected_techniques = attack.load_techniques_redirect()
    today = time.strftime("%Y/%m/%d")

    rules = RuleCollection.default()

    for rule in rules.rules:
        threat = rule.contents.data.threat or []
        new_threat_list: list[ThreatMapping] = []

        for entry in threat:
            technique_ids, technique_names = _threat_entry_technique_flat(entry)

            redirect_hit = any(tid in redirected_techniques for tid in technique_ids)
            name_drift = _legacy_technique_name_drift(technique_ids, technique_names)
            tactic_unknown = entry.framework == "MITRE ATT&CK" and entry.tactic.name not in attack.tactics_map

            if redirect_hit:
                click.echo(
                    f"'{rule.contents.name}' requires update - technique ID change for tactic '{entry.tactic.name}'"
                )
            elif name_drift:
                click.echo(
                    f"'{rule.contents.name}' requires update - technique name change for tactic '{entry.tactic.name}'"
                )

            refresh = redirect_hit or name_drift

            if entry.framework != "MITRE ATT&CK":
                new_threat_list.append(entry)
                continue

            if tactic_unknown:
                if not technique_ids:
                    only_name = attack.tactic_id_to_name.get(entry.tactic.id)
                    if not only_name:
                        raise ValueError(
                            f"{rule.id} - {rule.name}: MITRE tactic {entry.tactic.name!r} (id "
                            f"{entry.tactic.id!r}) is unknown to bundled ATT&CK data and no techniques "
                            "were listed to infer a replacement."
                        )
                    new_threat_list.append(
                        ThreatMapping.from_dict(attack.build_threat_map_entry(only_name))
                    )
                    continue
                retained = attack.retain_tactic_display_if_id_and_techniques_still_match(
                    entry.tactic.id, technique_ids
                )
                if retained is not None:
                    sorted_ids = sorted(set(technique_ids), key=lambda x: (x.split(".")[0], x))
                    new_threat_list.append(
                        ThreatMapping.from_dict(attack.build_threat_map_entry(retained, *sorted_ids))
                    )
                    continue
                row_tid = entry.tactic.id if entry.tactic.id in attack.tactic_id_to_name else None
                new_threat_list.extend(
                    ThreatMapping.from_dict(r)
                    for r in attack.rebuild_threat_dicts_from_technique_ids(
                        technique_ids, row_tactic_external_id=row_tid
                    )
                )
                continue

            if refresh:
                try:
                    rebuilt = attack.build_threat_map_entry(entry.tactic.name, *technique_ids)
                    new_threat_list.append(ThreatMapping.from_dict(rebuilt))
                except ValueError as exc:
                    raise ValueError(f"{rule.id} - {rule.name}: {exc}") from exc
            else:
                new_threat_list.append(entry)

        new_threat_list.sort(key=_mitre_threat_persist_sort_key)

        if _normalized_threat_signature(threat) == _normalized_threat_signature(new_threat_list):
            continue

        new_meta = dataclasses.replace(rule.contents.metadata, updated_date=today)
        new_data = dataclasses.replace(rule.contents.data, threat=new_threat_list)
        new_contents = dataclasses.replace(rule.contents, data=new_data, metadata=new_meta)
        new_rule = TOMLRule(contents=new_contents, path=rule.path)
        new_rule.save_toml()
        new_rules.append(new_rule)

    if new_rules:
        click.echo(f"\nFinished - {len(new_rules)} rules updated!")
    else:
        click.echo("No rule changes needed")
    return new_rules


@dev_group.group("transforms")
def transforms_group() -> None:
    """Commands for managing TOML [transform]."""


def guide_plugin_convert_(
    contents: str | None = None,
    default: str | None = "",
) -> dict[str, dict[str, list[str]]] | None:
    """Convert investigation guide plugin format to toml"""
    contents = contents or click.prompt("Enter plugin contents", default=default)
    if not contents:
        return None

    parsed = re.match(r"!{(?P<plugin>\w+)(?P<data>{.+})}", contents.strip())
    if not parsed:
        raise ValueError("No plugin name found")
    try:
        plugin = parsed.group("plugin")
        data = parsed.group("data")
    except AttributeError as e:
        raise raise_client_error("Unrecognized pattern", exc=e) from e
    loaded = {"transform": {plugin: [json.loads(data)]}}
    click.echo(pytoml.dumps(loaded))  # type: ignore[reportUnknownMemberType]
    return loaded


@transforms_group.command("guide-plugin-convert")
def guide_plugin_convert(
    contents: str | None = None, default: str | None = ""
) -> dict[str, dict[str, list[str]]] | None:
    """Convert investigation guide plugin format to toml."""
    return guide_plugin_convert_(contents=contents, default=default)


@transforms_group.command("guide-plugin-to-rule")
@click.argument("rule-path", type=Path)
@click.pass_context
def guide_plugin_to_rule(ctx: click.Context, rule_path: Path, save: bool = True) -> TOMLRule:
    """Convert investigation guide plugin format to toml and save to rule."""
    rc = RuleCollection()
    rule = rc.load_file(rule_path)

    transforms: dict[str, list[Any]] = defaultdict(list)
    existing_transform: RuleTransform | None = rule.contents.transform  # type: ignore[reportAssignmentType]
    transforms.update(existing_transform.to_dict() if existing_transform else {})

    click.secho("(blank line to continue)", fg="yellow")
    while True:
        loaded = ctx.invoke(guide_plugin_convert)
        if not loaded:
            break

        data = loaded["transform"]
        for plugin, entries in data.items():
            transforms[plugin].extend(entries)

    transform = RuleTransform.from_dict(transforms)
    new_contents = TOMLRuleContents(data=rule.contents.data, metadata=rule.contents.metadata, transform=transform)  # type: ignore[reportArgumentType]
    updated_rule = TOMLRule(contents=new_contents, path=rule.path)

    if save:
        updated_rule.save_toml()

    return updated_rule
