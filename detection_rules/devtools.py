# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""CLI commands for internal detection_rules dev team."""
import dataclasses
import functools
import hashlib
import io
import json
import os
import shutil
import subprocess
import textwrap
import time
import typing
from pathlib import Path
from typing import Dict, Optional, Tuple

import click
from elasticsearch import Elasticsearch

from kibana.connector import Kibana
from . import rule_loader
from .cli_utils import single_collection
from .eswrap import CollectEvents, add_range_to_dsl
from .ghwrap import GithubClient
from .main import root
from .misc import PYTHON_LICENSE, add_client, client_error
from .packaging import PACKAGE_FILE, Package, RELEASE_DIR, current_stack_version, manage_versions
from .rule import AnyRuleData, BaseRuleData, QueryRuleData, TOMLRule
from .rule_loader import RuleCollection, production_filter
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

    package = Package.from_config(config, update_version_lock=update_version_lock, verbose=verbose)
    package.save(verbose=verbose)

    if verbose:
        package.get_package_hash(verbose=True)
        click.echo(f'- {len(package.rules)} rules included')

    return package


@dev_group.command('update-lock-versions')
@click.argument('rule-ids', nargs=-1, required=True)
def update_lock_versions(rule_ids):
    """Update rule hashes in version.lock.json file without bumping version."""
    from .packaging import manage_versions

    if not click.confirm('Are you sure you want to update hashes without a version bump?'):
        return

    rules = RuleCollection.default().filter(lambda r: r.id in rule_ids)
    changed, new, _ = manage_versions(rules, exclude_version_update=True, add_new=False, save_changes=True)

    if not changed:
        click.echo('No hashes updated')

    return changed


@dev_group.command('kibana-diff')
@click.option('--rule-id', '-r', multiple=True, help='Optionally specify rule ID')
@click.option('--repo', default='elastic/kibana', help='Repository where branch is located')
@click.option('--branch', '-b', default='master', help='Specify the kibana branch to diff against')
@click.option('--threads', '-t', type=click.IntRange(1), default=50, help='Number of threads to use to download rules')
def kibana_diff(rule_id, repo, branch, threads):
    """Diff rules against their version represented in kibana if exists."""
    from .misc import get_kibana_rules

    rules = RuleCollection.default()

    if rule_id:
        rules = rules.filter(lambda r: r.id in rule_id).id_map
    else:
        rules = rules.filter(production_filter).id_map

    # add versions to the rules
    manage_versions(list(rules.values()), verbose=False)
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
    @click.option("--base-branch", "-b", help="Base branch in Kibana", default="master")
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
    git_exe = shutil.which("git")

    package_name = Package.load_configs()["name"]
    release_dir = os.path.join(RELEASE_DIR, package_name)
    message = message or f"[Detection Rules] Add {package_name} rules"

    if not os.path.exists(release_dir):
        click.secho("Release directory doesn't exist.", fg="red", err=True)
        click.echo(f"Run {click.style('python -m detection_rules dev build-release', bold=True)} to populate", err=True)
        ctx.exit(1)

    if not git_exe:
        click.secho("Unable to find git", err=True, fg="red")
        ctx.exit(1)

    # Get the current hash of the repo
    long_commit_hash = subprocess.check_output([git_exe, "rev-parse", "HEAD"], encoding="utf-8").strip()
    short_commit_hash = subprocess.check_output([git_exe, "rev-parse", "--short", "HEAD"], encoding="utf-8").strip()

    try:
        if not os.path.exists(local_repo):
            if not click.confirm(f"Kibana repository doesn't exist at {local_repo}. Clone?"):
                ctx.exit(1)

            url = f"git@github.com:{github_repo}.git" if ssh else f"https://github.com/{github_repo}.git"
            subprocess.check_call([git_exe, "clone", url, local_repo, "--depth", 1])

        def git(*args, show_output=False):
            method = subprocess.call if show_output else subprocess.check_output
            return method([git_exe, "-C", local_repo] + list(args), encoding="utf-8")

        branch_name = branch_name or f"detection-rules/{package_name}-{short_commit_hash}"

        git("checkout", base_branch)
        git("pull")
        git("checkout", "-b", branch_name, show_output=True)
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
        git("status", show_output=True)

        if push:
            git("push", "origin", branch_name)

        click.echo(f"Kibana repository {local_repo} prepped. Push changes when ready")
        click.secho(f"cd {local_repo}", bold=True)

        return branch_name, long_commit_hash

    except subprocess.CalledProcessError as e:
        client_error(str(e), e, ctx=ctx)


@dev_group.command("kibana-pr")
@click.option("--token", required=True, prompt=True, default=get_github_token(),
              help="GitHub token to use for the PR", hide_input=True)
@click.option("--assign", multiple=True, help="GitHub users to assign the PR")
@click.option("--label", multiple=True, help="GitHub labels to add to the PR")
# Pending an official GitHub API
# @click.option("--automerge", is_flag=True, help="Enable auto-merge on the PR")
@click.option("--draft", is_flag=True, help="Open the PR as a draft")
@add_git_args
@click.pass_context
def kibana_pr(ctx: click.Context, label: Tuple[str, ...], assign: Tuple[str, ...], draft: bool, token: str, **kwargs):
    """Create a pull request to Kibana."""
    branch_name, commit_hash = ctx.invoke(kibana_commit, push=True, **kwargs)
    client = GithubClient(token).authenticated_client
    repo = client.get_repo(kwargs["github_repo"])

    title = f"[Detection Engine] Adds {current_stack_version()} rules"
    body = textwrap.dedent(f"""
    ## Summary

    Pull updates to detection rules from https://github.com/elastic/detection-rules/tree/{commit_hash}.

    ### Checklist

    Delete any items that are not applicable to this PR.

    - [x] Any text added follows [EUI's writing guidelines](https://elastic.github.io/eui/#/guidelines/writing),
          uses sentence case text and includes [i18n support](https://github.com/elastic/kibana/blob/master/packages/kbn-i18n/README.md)
    """).strip()  # noqa: E501
    pr = repo.create_pull(title, body, kwargs["base_branch"], branch_name, draft=draft)

    label = set(label)
    if label:
        pr.add_to_labels(*sorted(label))

    if assign:
        pr.add_to_assignees(*assign)

    click.echo("PR created:")
    click.echo(pr.html_url)


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
    click.echo(f'New rules: {len(current_package.new_rules_ids)}')
    click.echo(f'Modified rules: {len(current_package.changed_rule_ids)}')
    click.echo(f'Deprecated rules: {len(current_package.removed_rule_ids)}')

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

    all_rules = {}
    new, modified, errors = rule_loader.load_github_pr_rules(token=token, threads=threads)

    def add_github_meta(this_rule: TOMLRule, status: str, original_rule_id: Optional[definitions.UUIDString] = None):
        pr = this_rule.gh_pr
        new_data = {}
        new_meta = {
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
            new_meta['original_rule_id'] = original_rule_id
            new_data = {'rule_id': str(uuid4())}

        rule_path = Path(f'pr-{pr.number}-{rule.path}')

        new_rule = this_rule.new(path=rule_path, data=dict(meta=new_meta, **new_data))

        rule_dict = {'metadata': new_rule.contents.metadata.to_dict(), 'rule': new_rule.contents.to_api_format()}
        all_rules[rule_path] = rule_dict

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
@click.argument('rule-file', type=click.Path(dir_okay=False))
@click.pass_context
def deprecate_rule(ctx: click.Context, rule_file: str):
    """Deprecate a rule."""
    import pytoml
    from .packaging import load_versions

    version_info = load_versions()
    rule_file = Path(rule_file)
    contents = TOMLRuleContents.from_dict(pytoml.loads(rule_file.read_text()))
    rule = TOMLRule(path=rule_file, contents=contents)

    if rule.contents.id not in version_info:
        click.echo('Rule has not been version locked and so does not need to be deprecated. '
                   'Delete the file or update the maturity to `development` instead')
        ctx.exit()

    today = time.strftime('%Y/%m/%d')

    new_meta = {
        'updated_date': today,
        'deprecation_date': today,
        'maturity': 'deprecated'
    }
    deprecated_path = get_path('rules', '_deprecated', rule_file.name)

    # create the new rule and save it
    new_rule = rule.new(path=Path(deprecated_path), metadata=new_meta)
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
