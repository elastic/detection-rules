# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""CLI commands for internal detection_rules dev team."""
import dataclasses
import functools
import io
import json
import os
import shutil
import subprocess
import textwrap
import time
import typing
from pathlib import Path
from typing import Dict, Optional, Tuple, List

import click
import yaml
from elasticsearch import Elasticsearch

from kibana.connector import Kibana
from . import rule_loader, utils
from .cli_utils import single_collection
from .docs import IntegrationSecurityDocs
from .eswrap import CollectEvents, add_range_to_dsl
from .ghwrap import GithubClient
from .main import root
from .misc import PYTHON_LICENSE, add_client, client_error
from .packaging import PACKAGE_FILE, Package, RELEASE_DIR, current_stack_version
from .version_lock import default_version_lock
from .rule import AnyRuleData, BaseRuleData, QueryRuleData, TOMLRule
from .rule_loader import RuleCollection, production_filter
from .schemas import definitions
from .semver import Version
from .utils import dict_hash, get_path, load_dump

RULES_DIR = get_path('rules')
GH_CONFIG = Path.home() / ".config" / "gh" / "hosts.yml"


def get_github_token() -> Optional[str]:
    """Get the current user's GitHub token."""
    token = os.getenv("GITHUB_TOKEN")

    if token is None and GH_CONFIG.exists():
        token = load_dump(str(GH_CONFIG)).get("github.com", {}).get("oauth_token")

    return token


@root.group('dev')
def dev_group():
    """Commands related to the Elastic Stack rules release lifecycle."""


@dev_group.command('build-release')
@click.argument('config-file', type=click.Path(exists=True, dir_okay=False), required=False, default=PACKAGE_FILE)
@click.option('--update-version-lock', '-u', is_flag=True,
              help='Save version.lock.json file with updated rule versions in the package')
def build_release(config_file, update_version_lock, release=None, verbose=True):
    """Assemble all the rules into Kibana-ready release files."""
    config = load_dump(config_file)['package']
    if release is not None:
        config['release'] = release

    if verbose:
        click.echo('[+] Building package {}'.format(config.get('name')))

    package = Package.from_config(config, verbose=verbose)

    if update_version_lock:
        default_version_lock.manage_versions(package.rules, save_changes=True, verbose=verbose)

    package.save(verbose=verbose)

    if verbose:
        package.get_package_hash(verbose=verbose)
        click.echo(f'- {len(package.rules)} rules included')

    return package


@dev_group.command('build-integration-docs')
@click.argument('registry-version')
@click.option('--pre', required=True, help='Tag for pre-existing rules')
@click.option('--post', required=True, help='Tag for rules post updates')
@click.option('--directory', '-d', type=Path, required=True, help='Output directory to save docs to')
@click.option('--force', '-f', is_flag=True, help='Bypass the confirmation prompt')
@click.option('--remote', '-r', default='origin', help='Override the remote from "origin"')
@click.pass_context
def build_integration_docs(ctx: click.Context, registry_version: str, pre: str, post: str, directory: Path, force: bool,
                           remote: Optional[str] = 'origin') -> IntegrationSecurityDocs:
    """Build documents from two git tags for an integration package."""
    if not force:
        if not click.confirm(f'This will refresh tags and may overwrite local tags for: {pre} and {post}. Continue?'):
            ctx.exit(1)

    pre_rules = RuleCollection()
    pre_rules.load_git_tag(pre, remote, skip_query_validation=True)

    if pre_rules.errors:
        click.echo(f'error loading {len(pre_rules.errors)} rule(s) from: {pre}, skipping:')
        click.echo(' - ' + '\n - '.join([str(p) for p in pre_rules.errors]))

    post_rules = RuleCollection()
    post_rules.load_git_tag(post, remote, skip_query_validation=True)

    if post_rules.errors:
        click.echo(f'error loading {len(post_rules.errors)} rule(s) from: {post}, skipping:')
        click.echo(' - ' + '\n - '.join([str(p) for p in post_rules.errors]))

    rules_changes = pre_rules.compare_collections(post_rules)

    docs = IntegrationSecurityDocs(registry_version, directory, True, *rules_changes)
    package_dir = docs.generate()
    click.echo(f'Generated documents saved to: {package_dir}')
    updated, new, deprecated = rules_changes
    click.echo(f'- {len(updated)} updated rules')
    click.echo(f'- {len(new)} new rules')
    click.echo(f'- {len(deprecated)} deprecated rules')

    return docs


@dataclasses.dataclass
class GitChangeEntry:
    status: str
    original_path: Path
    new_path: Optional[Path] = None

    @classmethod
    def from_line(cls, text: str) -> 'GitChangeEntry':
        columns = text.split("\t")
        assert 2 <= len(columns) <= 3

        columns[1:] = [Path(c) for c in columns[1:]]
        return cls(*columns)

    @property
    def path(self) -> Path:
        return self.new_path or self.original_path

    def revert(self, dry_run=False):
        """Run a git command to revert this change."""

        def git(*args):
            command_line = ["git"] + [str(arg) for arg in args]
            click.echo(subprocess.list2cmdline(command_line))

            if not dry_run:
                subprocess.check_call(command_line)

        if self.status.startswith("R"):
            # renames are actually Delete (D) and Add (A)
            # revert in opposite order
            GitChangeEntry("A", self.new_path).revert(dry_run=dry_run)
            GitChangeEntry("D", self.original_path).revert(dry_run=dry_run)
            return

        # remove the file from the staging area (A|M|D)
        git("restore", "--staged", self.original_path)

    def read(self, git_tree="HEAD") -> bytes:
        """Read the file from disk or git."""
        if self.status == "D":
            # deleted files need to be recovered from git
            return subprocess.check_output(["git", "show", f"{git_tree}:{self.path}"])

        return self.path.read_bytes()


@dev_group.command("unstage-incompatible-rules")
@click.option("--target-stack-version", "-t", help="Minimum stack version to filter the staging area", required=True)
@click.option("--dry-run", is_flag=True, help="List the changes that would be made")
def prune_staging_area(target_stack_version: str, dry_run: bool):
    """Prune the git staging area to remove changes to incompatible rules."""
    exceptions = {
        "etc/packages.yml",
    }

    target_stack_version = Version(target_stack_version)[:2]

    # load a structured summary of the diff from git
    git_output = subprocess.check_output(["git", "diff", "--name-status", "HEAD"])
    changes = [GitChangeEntry.from_line(line) for line in git_output.decode("utf-8").splitlines()]

    # track which changes need to be reverted because of incompatibilities
    reversions: List[GitChangeEntry] = []

    for change in changes:
        if str(change.path) in exceptions:
            # Don't backport any changes to files matching the list of exceptions
            reversions.append(change)
            continue

        # it's a change to a rule file, load it and check the version
        if str(change.path.absolute()).startswith(RULES_DIR) and change.path.suffix == ".toml":
            # bypass TOML validation in case there were schema changes
            dict_contents = RuleCollection.deserialize_toml_string(change.read())
            min_stack_version: Optional[str] = dict_contents.get("metadata", {}).get("min_stack_version")

            if min_stack_version is not None and target_stack_version < Version(min_stack_version)[:2]:
                # rule is incompatible, add to the list of reversions to make later
                reversions.append(change)

    if len(reversions) == 0:
        click.echo("No files restored from staging area")
        return

    click.echo(f"Restoring {len(reversions)} changes from the staging area...")
    for change in reversions:
        change.revert(dry_run=dry_run)


@dev_group.command('update-lock-versions')
@click.argument('rule-ids', nargs=-1, required=False)
def update_lock_versions(rule_ids):
    """Update rule hashes in version.lock.json file without bumping version."""
    rules = RuleCollection.default()

    if rule_ids:
        rules = rules.filter(lambda r: r.id in rule_ids)
    else:
        rules = rules.filter(production_filter)

    if not click.confirm(f'Are you sure you want to update hashes for {len(rules)} rules without a version bump?'):
        return

    # this command may not function as expected anymore due to previous changes eliminating the use of add_new=False
    changed, new, _ = default_version_lock.manage_versions(rules, exclude_version_update=True, save_changes=True)

    if not changed:
        click.echo('No hashes updated')

    return changed


@dev_group.command('kibana-diff')
@click.option('--rule-id', '-r', multiple=True, help='Optionally specify rule ID')
@click.option('--repo', default='elastic/kibana', help='Repository where branch is located')
@click.option('--branch', '-b', default='main', help='Specify the kibana branch to diff against')
@click.option('--threads', '-t', type=click.IntRange(1), default=50, help='Number of threads to use to download rules')
def kibana_diff(rule_id, repo, branch, threads):
    """Diff rules against their version represented in kibana if exists."""
    from .misc import get_kibana_rules

    rules = RuleCollection.default()

    if rule_id:
        rules = rules.filter(lambda r: r.id in rule_id).id_map
    else:
        rules = rules.filter(production_filter).id_map

    repo_hashes = {r.id: r.contents.sha256(include_version=True) for r in rules.values()}

    kibana_rules = {r['rule_id']: r for r in get_kibana_rules(repo=repo, branch=branch, threads=threads).values()}
    kibana_hashes = {r['rule_id']: dict_hash(r) for r in kibana_rules.values()}

    missing_from_repo = list(set(kibana_hashes).difference(set(repo_hashes)))
    missing_from_kibana = list(set(repo_hashes).difference(set(kibana_hashes)))

    rule_diff = []
    for rule_id, rule_hash in repo_hashes.items():
        if rule_id in missing_from_kibana:
            continue
        if rule_hash != kibana_hashes[rule_id]:
            rule_diff.append(
                f'versions - repo: {rules[rule_id].contents.autobumped_version}, '
                f'kibana: {kibana_rules[rule_id]["version"]} -> '
                f'{rule_id} - {rules[rule_id].contents.name}'
            )

    diff = {
        'missing_from_kibana': [f'{r} - {rules[r].name}' for r in missing_from_kibana],
        'diff': rule_diff,
        'missing_from_repo': [f'{r} - {kibana_rules[r]["name"]}' for r in missing_from_repo]
    }

    diff['stats'] = {k: len(v) for k, v in diff.items()}
    diff['stats'].update(total_repo_prod_rules=len(rules), total_gh_prod_rules=len(kibana_rules))

    click.echo(json.dumps(diff, indent=2, sort_keys=True))
    return diff


def add_git_args(f):
    @click.argument("local-repo", default=get_path("..", "kibana"))
    @click.option("--kibana-directory", "-d", help="Directory to overwrite in Kibana",
                  default="x-pack/plugins/security_solution/server/lib/detection_engine/rules/prepackaged_rules")
    @click.option("--base-branch", "-b", help="Base branch in Kibana", default="main")
    @click.option("--branch-name", "-n", help="New branch for the rules commit")
    @click.option("--ssh/--http", is_flag=True, help="Method to use for cloning")
    @click.option("--github-repo", "-r", help="Repository to use for the branch", default="elastic/kibana")
    @click.option("--message", "-m", help="Override default commit message")
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)

    return decorated


@dev_group.command("kibana-commit")
@add_git_args
@click.option("--push", "-p", is_flag=True, help="Push the commit to the remote")
@click.pass_context
def kibana_commit(ctx, local_repo: str, github_repo: str, ssh: bool, kibana_directory: str, base_branch: str,
                  branch_name: Optional[str], message: Optional[str], push: bool) -> (str, str):
    """Prep a commit and push to Kibana."""
    package_name = Package.load_configs()["name"]
    release_dir = os.path.join(RELEASE_DIR, package_name)
    message = message or f"[Detection Rules] Add {package_name} rules"

    if not os.path.exists(release_dir):
        click.secho("Release directory doesn't exist.", fg="red", err=True)
        click.echo(f"Run {click.style('python -m detection_rules dev build-release', bold=True)} to populate", err=True)
        ctx.exit(1)

    git = utils.make_git("-C", local_repo)
    rules_git = utils.make_git('-C', utils.get_path())

    # Get the current hash of the repo
    long_commit_hash = rules_git("rev-parse", "HEAD")
    short_commit_hash = rules_git("rev-parse", "--short", "HEAD")

    try:
        if not os.path.exists(local_repo):
            click.echo(f"Kibana repository doesn't exist at {local_repo}. Cloning...")
            url = f"git@github.com:{github_repo}.git" if ssh else f"https://github.com/{github_repo}.git"
            utils.make_git()("clone", url, local_repo, "--depth", "1")
        else:
            git("checkout", base_branch)

        branch_name = branch_name or f"detection-rules/{package_name}-{short_commit_hash}"

        git("checkout", "-b", branch_name, print_output=True)
        git("rm", "-r", kibana_directory)

        source_dir = os.path.join(release_dir, "rules")
        target_dir = os.path.join(local_repo, kibana_directory)
        os.makedirs(target_dir)

        for name in os.listdir(source_dir):
            _, ext = os.path.splitext(name)
            path = os.path.join(source_dir, name)

            if ext in (".ts", ".json"):
                shutil.copyfile(path, os.path.join(target_dir, name))

        git("add", kibana_directory)
        git("commit", "--no-verify", "-m", message)
        git("status", print_output=True)

        if push:
            git("push", "origin", branch_name)

        click.echo(f"Kibana repository {local_repo} prepped. Push changes when ready")
        click.secho(f"cd {local_repo}", bold=True)

        return branch_name, long_commit_hash

    except subprocess.CalledProcessError as e:
        client_error(str(e), e, ctx=ctx)


@dev_group.command("kibana-pr")
@click.option("--token", required=True, prompt=get_github_token() is None, default=get_github_token(),
              help="GitHub token to use for the PR", hide_input=True)
@click.option("--assign", multiple=True, help="GitHub users to assign the PR")
@click.option("--label", multiple=True, help="GitHub labels to add to the PR")
@click.option("--draft", is_flag=True, help="Open the PR as a draft")
@click.option("--fork-owner", "-f", help="Owner of forked branch (ex: elastic)")
# Pending an official GitHub API
# @click.option("--automerge", is_flag=True, help="Enable auto-merge on the PR")
@add_git_args
@click.pass_context
def kibana_pr(ctx: click.Context, label: Tuple[str, ...], assign: Tuple[str, ...], draft: bool, fork_owner: str,
              token: str, **kwargs):
    """Create a pull request to Kibana."""
    github = GithubClient(token)
    client = github.authenticated_client
    repo = client.get_repo(kwargs["github_repo"])

    branch_name, commit_hash = ctx.invoke(kibana_commit, push=True, **kwargs)

    if fork_owner:
        branch_name = f'{fork_owner}:{branch_name}'

    title = f"[Detection Engine] Adds {current_stack_version()} rules"
    body = textwrap.dedent(f"""
    ## Summary

    Pull updates to detection rules from https://github.com/elastic/detection-rules/tree/{commit_hash}.

    ### Checklist

    Delete any items that are not applicable to this PR.

    - [x] Any text added follows [EUI's writing guidelines](https://elastic.github.io/eui/#/guidelines/writing),
          uses sentence case text and includes [i18n support](https://github.com/elastic/kibana/blob/main/packages/kbn-i18n/README.md)
    """).strip()  # noqa: E501
    pr = repo.create_pull(title, body, base=kwargs["base_branch"], head=branch_name, maintainer_can_modify=True,
                          draft=draft)

    # labels could also be comma separated
    label = {lbl for cs_labels in label for lbl in cs_labels.split(",") if lbl}

    if label:
        pr.add_to_labels(*sorted(label))

    if assign:
        pr.add_to_assignees(*assign)

    click.echo("PR created:")
    click.echo(pr.html_url)


@dev_group.command("integrations-pr")
@click.argument("local-repo", type=click.Path(exists=True, file_okay=False, dir_okay=True),
                default=get_path("..", "integrations"))
@click.option("--token", required=True, prompt=get_github_token() is None, default=get_github_token(),
              help="GitHub token to use for the PR", hide_input=True)
@click.option("--pkg-directory", "-d", help="Directory to save the package in cloned repository",
              default=os.path.join("packages", "security_detection_engine"))
@click.option("--base-branch", "-b", help="Base branch in target repository", default="main")
@click.option("--branch-name", "-n", help="New branch for the rules commit")
@click.option("--github-repo", "-r", help="Repository to use for the branch", default="elastic/integrations")
@click.option("--assign", multiple=True, help="GitHub users to assign the PR")
@click.option("--label", multiple=True, help="GitHub labels to add to the PR")
@click.option("--draft", is_flag=True, help="Open the PR as a draft")
@click.option("--remote", help="Override the remote from 'origin'", default="origin")
@click.pass_context
def integrations_pr(ctx: click.Context, local_repo: str, token: str, draft: bool,
                    pkg_directory: str, base_branch: str, remote: str,
                    branch_name: Optional[str], github_repo: str, assign: Tuple[str, ...], label: Tuple[str, ...]):
    """Create a pull request to publish the Fleet package to elastic/integrations."""
    github = GithubClient(token)
    github.assert_github()
    client = github.authenticated_client
    repo = client.get_repo(github_repo)

    # Use elastic-package to format and lint
    gopath = utils.gopath()
    assert gopath is not None, "$GOPATH isn't set"

    err = 'elastic-package missing, run: go install github.com/elastic/elastic-package@latest and verify go bin path'
    assert subprocess.check_output(['elastic-package'], stderr=subprocess.DEVNULL), err

    local_repo = os.path.abspath(local_repo)
    stack_version = Package.load_configs()["name"]
    package_version = Package.load_configs()["registry_data"]["version"]

    release_dir = Path(RELEASE_DIR) / stack_version / "fleet" / package_version
    message = f"[Security Rules] Update security rules package to v{package_version}"

    if not release_dir.exists():
        click.secho("Release directory doesn't exist.", fg="red", err=True)
        click.echo(f"Run {click.style('python -m detection_rules dev build-release', bold=True)} to populate", err=True)
        ctx.exit(1)

    if not Path(local_repo).exists():
        click.secho(f"{github_repo} is not present at {local_repo}.", fg="red", err=True)
        ctx.exit(1)

    # Get the most recent commit hash of detection-rules
    detection_rules_git = utils.make_git()
    long_commit_hash = detection_rules_git("rev-parse", "HEAD")
    short_commit_hash = detection_rules_git("rev-parse", "--short", "HEAD")

    # refresh the local clone of the repository
    git = utils.make_git("-C", local_repo)
    git("checkout", base_branch)
    git("pull", remote, base_branch)

    # Switch to a new branch in elastic/integrations
    branch_name = branch_name or f"detection-rules/{package_version}-{short_commit_hash}"
    git("checkout", "-b", branch_name)

    # Load the changelog in memory, before it's removed. Come back for it after the PR is created
    target_directory = Path(local_repo) / pkg_directory
    changelog_path = target_directory / "changelog.yml"
    changelog_entries: list = yaml.safe_load(changelog_path.read_text(encoding="utf-8"))

    changelog_entries.insert(0, {
        "version": package_version,
        "changes": [
            # This will be changed later
            {"description": "Release security rules update", "type": "enhancement",
             "link": "https://github.com/elastic/integrations/pulls/0000"}
        ]
    })

    # Remove existing assets and replace everything
    shutil.rmtree(target_directory)
    actual_target_directory = shutil.copytree(release_dir, target_directory)
    assert Path(actual_target_directory).absolute() == Path(target_directory).absolute(), \
        f"Expected a copy to {pkg_directory}"

    # Add the changelog back
    def save_changelog():
        with changelog_path.open("wt") as f:
            # add a note for other maintainers of elastic/integrations to be careful with versions
            f.write("# newer versions go on top\n")
            f.write("# NOTE: please use pre-release versions (e.g. -dev.0) until a package is ready for production\n")

            yaml.dump(changelog_entries, f, allow_unicode=True, default_flow_style=False, indent=2)

    save_changelog()

    def elastic_pkg(*args):
        """Run a command with $GOPATH/bin/elastic-package in the package directory."""
        prev = os.path.abspath(os.getcwd())
        os.chdir(target_directory)

        try:
            return subprocess.check_call([os.path.join(gopath, "bin", "elastic-package")] + list(args))
        finally:
            os.chdir(prev)

    elastic_pkg("format")
    elastic_pkg("lint")

    # Upload the files to a branch
    git("add", pkg_directory)
    git("commit", "-m", message)
    git("push", "--set-upstream", remote, branch_name)

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

    pr = repo.create_pull(message, body, base_branch, branch_name, maintainer_can_modify=True, draft=draft)

    # labels could also be comma separated
    label = {lbl for cs_labels in label for lbl in cs_labels.split(",") if lbl}

    if label:
        pr.add_to_labels(*sorted(label))

    if assign:
        pr.add_to_assignees(*assign)

    click.echo("PR created:")
    click.echo(pr.html_url)

    # replace the changelog entry with the actual PR link
    changelog_entries[0]["changes"][0]["link"] = pr.html_url
    save_changelog()

    # format the yml file with elastic-package
    elastic_pkg("format")
    elastic_pkg("lint")

    # Push the updated changelog to the PR branch
    git("add", pkg_directory)
    git("commit", "-m", f"Add changelog entry for {package_version}")
    git("push")


@dev_group.command('license-check')
@click.option('--ignore-directory', '-i', multiple=True, help='Directories to skip (relative to base)')
@click.pass_context
def license_check(ctx, ignore_directory):
    """Check that all code files contain a valid license."""
    ignore_directory += ("env",)
    failed = False
    base_path = Path(get_path())

    for path in base_path.rglob('*.py'):
        relative_path = path.relative_to(base_path)
        if relative_path.parts[0] in ignore_directory:
            continue

        with io.open(path, "rt", encoding="utf-8") as f:
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


@dev_group.command('package-stats')
@click.option('--token', '-t', help='GitHub token to search API authenticated (may exceed threshold without auth)')
@click.option('--threads', default=50, help='Number of threads to download rules from GitHub')
@click.pass_context
def package_stats(ctx, token, threads):
    """Get statistics for current rule package."""
    current_package: Package = ctx.invoke(build_release, verbose=False, release=None)
    release = f'v{current_package.name}.0'
    new, modified, errors = rule_loader.load_github_pr_rules(labels=[release], token=token, threads=threads)

    click.echo(f'Total rules as of {release} package: {len(current_package.rules)}')
    click.echo(f'New rules: {len(current_package.new_ids)}')
    click.echo(f'Modified rules: {len(current_package.changed_ids)}')
    click.echo(f'Deprecated rules: {len(current_package.removed_ids)}')

    click.echo('\n-----\n')
    click.echo('Rules in active PRs for current package: ')
    click.echo(f'New rules: {len(new)}')
    click.echo(f'Modified rules: {len(modified)}')


@dev_group.command('search-rule-prs')
@click.argument('query', required=False)
@click.option('--no-loop', '-n', is_flag=True, help='Run once with no loop')
@click.option('--columns', '-c', multiple=True, help='Specify columns to add the table')
@click.option('--language', type=click.Choice(["eql", "kql"]), default="kql")
@click.option('--token', '-t', help='GitHub token to search API authenticated (may exceed threshold without auth)')
@click.option('--threads', default=50, help='Number of threads to download rules from GitHub')
@click.pass_context
def search_rule_prs(ctx, no_loop, query, columns, language, token, threads):
    """Use KQL or EQL to find matching rules from active GitHub PRs."""
    from uuid import uuid4
    from .main import search_rules

    all_rules: Dict[Path, TOMLRule] = {}
    new, modified, errors = rule_loader.load_github_pr_rules(token=token, threads=threads)

    def add_github_meta(this_rule: TOMLRule, status: str, original_rule_id: Optional[definitions.UUIDString] = None):
        pr = this_rule.gh_pr
        data = rule.contents.data
        extend_meta = {
            'status': status,
            'github': {
                'base': pr.base.label,
                'comments': [c.body for c in pr.get_comments()],
                'commits': pr.commits,
                'created_at': str(pr.created_at),
                'head': pr.head.label,
                'is_draft': pr.draft,
                'labels': [lbl.name for lbl in pr.get_labels()],
                'last_modified': str(pr.last_modified),
                'title': pr.title,
                'url': pr.html_url,
                'user': pr.user.login
            }
        }

        if original_rule_id:
            extend_meta['original_rule_id'] = original_rule_id
            data = dataclasses.replace(rule.contents.data, rule_id=str(uuid4()))

        rule_path = Path(f'pr-{pr.number}-{rule.path}')
        new_meta = dataclasses.replace(rule.contents.metadata, extended=extend_meta)
        contents = dataclasses.replace(rule.contents, metadata=new_meta, data=data)
        new_rule = TOMLRule(path=rule_path, contents=contents)

        all_rules[new_rule.path] = new_rule

    for rule_id, rule in new.items():
        add_github_meta(rule, 'new')

    for rule_id, rules in modified.items():
        for rule in rules:
            add_github_meta(rule, 'modified', rule_id)

    loop = not no_loop
    ctx.invoke(search_rules, query=query, columns=columns, language=language, rules=all_rules, pager=loop)

    while loop:
        query = click.prompt(f'Search loop - enter new {language} query or ctrl-z to exit')
        columns = click.prompt('columns', default=','.join(columns)).split(',')
        ctx.invoke(search_rules, query=query, columns=columns, language=language, rules=all_rules, pager=True)


@dev_group.command('deprecate-rule')
@click.argument('rule-file', type=Path)
@click.pass_context
def deprecate_rule(ctx: click.Context, rule_file: Path):
    """Deprecate a rule."""
    version_info = default_version_lock.version_lock
    rule_collection = RuleCollection()
    contents = rule_collection.load_file(rule_file).contents
    rule = TOMLRule(path=rule_file, contents=contents)

    if rule.contents.id not in version_info:
        click.echo('Rule has not been version locked and so does not need to be deprecated. '
                   'Delete the file or update the maturity to `development` instead')
        ctx.exit()

    today = time.strftime('%Y/%m/%d')
    deprecated_path = get_path('rules', '_deprecated', rule_file.name)

    # create the new rule and save it
    new_meta = dataclasses.replace(rule.contents.metadata,
                                   updated_date=today,
                                   deprecation_date=today,
                                   maturity='deprecated')
    contents = dataclasses.replace(rule.contents, metadata=new_meta)
    new_rule = TOMLRule(contents=contents, path=Path(deprecated_path))
    new_rule.save_toml()

    # remove the old rule
    rule_file.unlink()
    click.echo(f'Rule moved to {deprecated_path} - remember to git add this file')


@dev_group.command("update-schemas")
def update_schemas():
    classes = [BaseRuleData] + list(typing.get_args(AnyRuleData))

    for cls in classes:
        cls.save_schema()


@dev_group.group('test')
def test_group():
    """Commands for testing against stack resources."""


@test_group.command('event-search')
@click.argument('query')
@click.option('--index', '-i', multiple=True, help='Index patterns to search against')
@click.option('--eql/--lucene', '-e/-l', 'language', default=None, help='Query language used (default: kql)')
@click.option('--date-range', '-d', type=(str, str), default=('now-7d', 'now'), help='Date range to scope search')
@click.option('--count', '-c', is_flag=True, help='Return count of results only')
@click.option('--max-results', '-m', type=click.IntRange(1, 1000), default=100,
              help='Max results to return (capped at 1000)')
@click.option('--verbose', '-v', is_flag=True, default=True)
@add_client('elasticsearch')
def event_search(query, index, language, date_range, count, max_results, verbose=True,
                 elasticsearch_client: Elasticsearch = None):
    """Search using a query against an Elasticsearch instance."""
    start_time, end_time = date_range
    index = index or ('*',)
    language_used = "kql" if language is None else "eql" if language is True else "lucene"
    collector = CollectEvents(elasticsearch_client, max_results)

    if verbose:
        click.echo(f'searching {",".join(index)} from {start_time} to {end_time}')
        click.echo(f'{language_used}: {query}')

    if count:
        results = collector.count(query, language_used, index, start_time, end_time)
        click.echo(f'total results: {results}')
    else:
        results = collector.search(query, language_used, index, start_time, end_time, max_results)
        click.echo(f'total results: {len(results)} (capped at {max_results})')
        click.echo_via_pager(json.dumps(results, indent=2, sort_keys=True))

    return results


@test_group.command('rule-event-search')
@single_collection
@click.option('--date-range', '-d', type=(str, str), default=('now-7d', 'now'), help='Date range to scope search')
@click.option('--count', '-c', is_flag=True, help='Return count of results only')
@click.option('--max-results', '-m', type=click.IntRange(1, 1000), default=100,
              help='Max results to return (capped at 1000)')
@click.option('--verbose', '-v', is_flag=True)
@click.pass_context
@add_client('elasticsearch')
def rule_event_search(ctx, rule, date_range, count, max_results, verbose,
                      elasticsearch_client: Elasticsearch = None):
    """Search using a rule file against an Elasticsearch instance."""

    if isinstance(rule.contents.data, QueryRuleData):
        if verbose:
            click.echo(f'Searching rule: {rule.name}')

        data = rule.contents.data
        rule_lang = data.language

        if rule_lang == 'kuery':
            language_flag = None
        elif rule_lang == 'eql':
            language_flag = True
        else:
            language_flag = False

        index = data.index or ['*']
        ctx.invoke(event_search, query=data.query, index=index, language=language_flag,
                   date_range=date_range, count=count, max_results=max_results, verbose=verbose,
                   elasticsearch_client=elasticsearch_client)
    else:
        client_error('Rule is not a query rule!')


@test_group.command('rule-survey')
@click.argument('query', required=False)
@click.option('--date-range', '-d', type=(str, str), default=('now-7d', 'now'), help='Date range to scope search')
@click.option('--dump-file', type=click.Path(dir_okay=False),
              default=get_path('surveys', f'{time.strftime("%Y%m%dT%H%M%SL")}.json'),
              help='Save details of results (capped at 1000 results/rule)')
@click.option('--hide-zero-counts', '-z', is_flag=True, help='Exclude rules with zero hits from printing')
@click.option('--hide-errors', '-e', is_flag=True, help='Exclude rules with errors from printing')
@click.pass_context
@add_client('elasticsearch', 'kibana', add_to_ctx=True)
def rule_survey(ctx: click.Context, query, date_range, dump_file, hide_zero_counts, hide_errors,
                elasticsearch_client: Elasticsearch = None, kibana_client: Kibana = None):
    """Survey rule counts."""
    from eql.table import Table
    from kibana.resources import Signal
    from .main import search_rules

    survey_results = []
    start_time, end_time = date_range

    if query:
        rules = RuleCollection()
        paths = [Path(r['file']) for r in ctx.invoke(search_rules, query=query, verbose=False)]
        rules.load_files(paths)
    else:
        rules = RuleCollection.default().filter(production_filter)

    click.echo(f'Running survey against {len(rules)} rules')
    click.echo(f'Saving detailed dump to: {dump_file}')

    collector = CollectEvents(elasticsearch_client)
    details = collector.search_from_rule(*rules, start_time=start_time, end_time=end_time)
    counts = collector.count_from_rule(*rules, start_time=start_time, end_time=end_time)

    # add alerts
    with kibana_client:
        range_dsl = {'query': {'bool': {'filter': []}}}
        add_range_to_dsl(range_dsl['query']['bool']['filter'], start_time, end_time)
        alerts = {a['_source']['signal']['rule']['rule_id']: a['_source']
                  for a in Signal.search(range_dsl)['hits']['hits']}

    for rule_id, count in counts.items():
        alert_count = len(alerts.get(rule_id, []))
        if alert_count > 0:
            count['alert_count'] = alert_count

        details[rule_id].update(count)

        search_count = count['search_count']
        if not alert_count and (hide_zero_counts and search_count == 0) or (hide_errors and search_count == -1):
            continue

        survey_results.append(count)

    fields = ['rule_id', 'name', 'search_count', 'alert_count']
    table = Table.from_list(fields, survey_results)

    if len(survey_results) > 200:
        click.echo_via_pager(table)
    else:
        click.echo(table)

    os.makedirs(get_path('surveys'), exist_ok=True)
    with open(dump_file, 'w') as f:
        json.dump(details, f, indent=2, sort_keys=True)

    return survey_results
