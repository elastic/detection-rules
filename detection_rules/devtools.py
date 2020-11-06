# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""CLI commands for internal detection_rules dev team."""
import glob
import io
import json
import os
import shutil
import subprocess
import time
from collections import defaultdict

import click
import elasticsearch
from elasticsearch import Elasticsearch
from elasticsearch.client import AsyncSearchClient
from eql import load_dump
from kibana.connector import Kibana

from . import rule_loader
from .eswrap import add_range_to_dsl
from .main import root
from .misc import PYTHON_LICENSE, add_client, client_error
from .packaging import PACKAGE_FILE, Package, manage_versions, RELEASE_DIR
from .rule import Rule
from .rule_loader import get_rule
from .utils import get_path


RULES_DIR = get_path('rules')


@root.group('dev')
def dev_group():
    """Commands related to the Elastic Stack rules release lifecycle."""


@dev_group.command('build-release')
@click.argument('config-file', type=click.Path(exists=True, dir_okay=False), required=False, default=PACKAGE_FILE)
@click.option('--update-version-lock', '-u', is_flag=True,
              help='Save version.lock.json file with updated rule versions in the package')
def build_release(config_file, update_version_lock):
    """Assemble all the rules into Kibana-ready release files."""
    config = load_dump(config_file)['package']
    click.echo('[+] Building package {}'.format(config.get('name')))
    package = Package.from_config(config, update_version_lock=update_version_lock, verbose=True)
    package.save()
    package.get_package_hash(verbose=True)
    click.echo('- {} rules included'.format(len(package.rules)))


@dev_group.command('update-lock-versions')
@click.argument('rule-ids', nargs=-1, required=True)
def update_lock_versions(rule_ids):
    """Update rule hashes in version.lock.json file without bumping version."""
    from .packaging import manage_versions

    if not click.confirm('Are you sure you want to update hashes without a version bump?'):
        return

    rules = [r for r in rule_loader.load_rules(verbose=False).values() if r.id in rule_ids]
    changed, new = manage_versions(rules, exclude_version_update=True, add_new=False, save_changes=True)

    if not changed:
        click.echo('No hashes updated')

    return changed


@dev_group.command('kibana-diff')
@click.option('--rule-id', '-r', multiple=True, help='Optionally specify rule ID')
@click.option('--branch', '-b', default='master', help='Specify the kibana branch to diff against')
@click.option('--threads', '-t', type=click.IntRange(1), default=50, help='Number of threads to use to download rules')
def kibana_diff(rule_id, branch, threads):
    """Diff rules against their version represented in kibana if exists."""
    from .misc import get_kibana_rules

    if rule_id:
        rules = {r.id: r for r in rule_loader.load_rules(verbose=False).values() if r.id in rule_id}
    else:
        rules = {r.id: r for r in rule_loader.get_production_rules()}

    # add versions to the rules
    manage_versions(list(rules.values()), verbose=False)
    repo_hashes = {r.id: r.get_hash() for r in rules.values()}

    kibana_rules = {r['rule_id']: r for r in get_kibana_rules(branch=branch, threads=threads).values()}
    kibana_hashes = {r['rule_id']: Rule.dict_hash(r) for r in kibana_rules.values()}

    missing_from_repo = list(set(kibana_hashes).difference(set(repo_hashes)))
    missing_from_kibana = list(set(repo_hashes).difference(set(kibana_hashes)))

    rule_diff = []
    for rid, rhash in repo_hashes.items():
        if rid in missing_from_kibana:
            continue
        if rhash != kibana_hashes[rid]:
            rule_diff.append(
                f'versions - repo: {rules[rid].contents["version"]}, kibana: {kibana_rules[rid]["version"]} -> '
                f'{rid} - {rules[rid].name}'
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


@dev_group.command("kibana-commit")
@click.argument("local-repo", default=get_path("..", "kibana"))
@click.option("--kibana-directory", "-d", help="Directory to overwrite in Kibana",
              default="x-pack/plugins/security_solution/server/lib/detection_engine/rules/prepackaged_rules")
@click.option("--base-branch", "-b", help="Base branch in Kibana", default="master")
@click.option("--ssh/--http", is_flag=True, help="Method to use for cloning")
@click.option("--github-repo", "-r", help="Repository to use for the branch", default="elastic/kibana")
@click.option("--message", "-m", help="Override default commit message")
@click.pass_context
def kibana_commit(ctx, local_repo, github_repo, ssh, kibana_directory, base_branch, message):
    """Prep a commit and push to Kibana."""
    git_exe = shutil.which("git")

    package_name = load_dump(PACKAGE_FILE)['package']["name"]
    release_dir = os.path.join(RELEASE_DIR, package_name)
    message = message or f"[Detection Rules] Add {package_name} rules"

    if not os.path.exists(release_dir):
        click.secho("Release directory doesn't exist.", fg="red", err=True)
        click.echo(f"Run {click.style('python -m detection_rules build-release', bold=True)} to populate", err=True)
        ctx.exit(1)

    if not git_exe:
        click.secho("Unable to find git", err=True, fg="red")
        ctx.exit(1)

    try:
        if not os.path.exists(local_repo):
            if not click.confirm(f"Kibana repository doesn't exist at {local_repo}. Clone?"):
                ctx.exit(1)

            url = f"git@github.com:{github_repo}.git" if ssh else f"https://github.com/{github_repo}.git"
            subprocess.check_call([git_exe, "clone", url, local_repo, "--depth", 1])

        def git(*args, show_output=False):
            method = subprocess.call if show_output else subprocess.check_output
            return method([git_exe, "-C", local_repo] + list(args), encoding="utf-8")

        git("checkout", base_branch)
        git("pull")
        git("checkout", "-b", f"rules/{package_name}", show_output=True)
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

        git("commit", "-S", "-m", message)
        git("status", show_output=True)

        click.echo(f"Kibana repository {local_repo} prepped. Push changes when ready")
        click.secho(f"cd {local_repo}", bold=True)

    except subprocess.CalledProcessError as e:
        client_error(e.returncode, e, ctx=ctx)


@dev_group.command('license-check')
@click.pass_context
def license_check(ctx):
    """Check that all code files contain a valid license."""

    failed = False

    for path in glob.glob(get_path("**", "*.py"), recursive=True):
        if path.startswith(get_path("env", "")):
            continue

        relative_path = os.path.relpath(path)

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


@dev_group.group('test')
def test_group():
    """Commands for testing against stack resources."""


@test_group.command('event-search')
@click.argument('query')
@click.option('--index', '-i', multiple=True, required=True, help='Index(es) to search against ("*": for all indexes)')
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
    import kql

    language_used = "kql" if language is None else "eql" if language is True else "lucene"

    index_str = ','.join(index)
    formatted_query = {'query': kql.to_dsl(query)} if language_used == 'kql' else \
        {'query': query} if language_used == 'eql' else {'query': {'bool': {'filter': []}}}  # lucene

    # add range to query - for dsl: add to filter, for lucene and eql: build new and add to body[filter]
    start_time, end_time = date_range
    if language_used in ('kql', 'lucene'):
        add_range_to_dsl(formatted_query['query']['bool'].setdefault('filter', []), start_time, end_time)
    elif language_used == 'eql':
        formatted_query['filter'] = {'bool': {'filter': [{'match_all': {}}]}}
        add_range_to_dsl(formatted_query['filter']['bool']['filter'], start_time, end_time)

    if verbose:
        click.echo(f'searching {index_str} from {start_time} to {end_time}')
        click.echo(f'{language_used}: {formatted_query or query}')

    results = []
    if language_used == 'eql':
        formatted_query['size'] = 1000 if count else max_results
        results = elasticsearch_client.eql.search(body=formatted_query, index=index_str)['hits']
        results = results.get('events') or results.get('sequences', [])

    if count:
        # EQL API has no count endpoint
        if language_used == 'eql':
            count = len(results)
        else:
            count = elasticsearch_client.count(body=formatted_query, index=index_str)
            click.echo(f'Total results: {count["count"]}')

        return count
    else:
        # EQL search results will pass through from above
        if language_used != 'eql':
            results = elasticsearch_client.search(body=formatted_query, q=query if language_used == 'lucene' else None,
                                                  index=index_str, size=max_results)['hits']['hits']

        click.echo(f'total results: {len(results)}')
        click.echo_via_pager(json.dumps(results, indent=2, sort_keys=True))
        return results


@test_group.command('rule-event-search')
@click.argument('rule-file', type=click.Path(dir_okay=False), required=False)
@click.option('--rule-id', '-id')
@click.option('--date-range', '-d', type=(str, str), default=('now-7d', 'now'), help='Date range to scope search')
@click.option('--count', '-c', is_flag=True, help='Return count of results only')
@click.option('--verbose', '-v', is_flag=True)
@click.pass_context
@add_client('elasticsearch')
def rule_event_search(ctx, rule_file, rule_id, date_range, count, verbose, elasticsearch_client: Elasticsearch = None):
    """Search using a rule file against an Elasticsearch instance."""
    rule = None

    if rule_id:
        rule = get_rule(rule_id, verbose=False)
    elif rule_file:
        rule = Rule(rule_file, load_dump(rule_file))
    else:
        client_error('Must specify a rule file or rule ID')

    if rule.contents.get('query') and rule.contents.get('language'):
        if verbose:
            click.echo(f'Searching rule: {rule.name}')

        rule_lang = rule.contents.get('language')
        language = None if rule_lang == 'kuery' else True if rule_lang == 'eql' else "lucene"
        ctx.invoke(event_search, query=rule.query, index=rule.contents.get('index', "*"), language=language,
                   date_range=date_range, count=count, verbose=verbose, elasticsearch_client=elasticsearch_client)
    else:
        client_error('Rule is not a query rule!')


@test_group.command('rule-survey')
@click.argument('query', required=False)
@click.option('--date-range', '-d', type=(str, str), default=('now-7d', 'now'), help='Date range to scope search')
@click.option('--dump-file', type=click.Path(dir_okay=False),
              default=get_path('surveys', f'{time.strftime("%Y%m%dT%H%M%SL")}.json'),
              help='Save details of results (capped at 1000 results/rule) (warning: potentially resource intensive)')
@click.option('--hide-zero-counts', '-z', is_flag=True, help='Exclude rules with zero hits from printing')
@click.option('--hide-errors', '-e', is_flag=True, help='Exclude rules with errors from printing')
@click.pass_context
@add_client('elasticsearch', 'kibana', add_to_ctx=True)
def rule_survey(ctx: click.Context, query, date_range, dump_file, hide_zero_counts, hide_errors,
                elasticsearch_client: Elasticsearch = None, kibana_client: Kibana = None):
    """Survey rule counts."""
    import kql
    from eql.table import Table
    from kibana.resources import Signal
    from . import rule_loader
    from .main import search_rules

    survey_results = []
    start_time, end_time = date_range

    if query:
        rule_paths = [r['file'] for r in ctx.invoke(search_rules, query=query, verbose=False)]
        rules = rule_loader.load_rules(rule_loader.load_rule_files(paths=rule_paths, verbose=False), verbose=False)
        rules = rules.values()
    else:
        rules = rule_loader.load_rules(verbose=False).values()

    click.echo(f'Running survey against {len(rules)} rules')
    click.echo(f'Saving detailed dump to: {dump_file}')
    details = get_detailed_search_results(elasticsearch_client, rules, start_time, end_time)

    # add alerts
    with kibana_client:
        range_dsl = {'query': {'bool': {'filter': []}}}
        add_range_to_dsl(range_dsl['query']['bool']['filter'], start_time, end_time)
        alerts = {a['_source']['signal']['rule']['rule_id']: a['_source']
                  for a in Signal.search(range_dsl)['hits']['hits']}

    for rule in rules:
        rule_results = {'rule_id': rule.id, 'name': rule.name}
        if not rule.contents.get('query'):
            continue

        index = ','.join(rule.contents['index'])
        language = rule.contents.get('language')
        is_kql = language == 'kuery'
        is_lucene = language == 'lucene'
        is_eql = language == 'eql'

        # dsl filter for date ranges for lucene and eql (kql is already dsl and so will mutate filter)
        range_dsl = {'query': {'bool': {'filter': []}}}
        add_range_to_dsl(range_dsl['query']['bool']['filter'], start_time, end_time)

        try:
            if is_kql:
                kql_query = kql.to_dsl(rule.query)
                add_range_to_dsl(kql_query['bool'].setdefault('filter', []), start_time, end_time)
                result = elasticsearch_client.count({'query': kql_query}, index=index)
                rule_results['search_count'] = result['count']
            elif is_lucene:
                result = elasticsearch_client.count(body=range_dsl, q=rule.query, index=index)
                rule_results['search_count'] = result['count']
            elif is_eql:
                # EQL API has no count endpoint, so just count results
                rule_results['search_count'] = len(details[rule.id].get('results', []))
        except elasticsearch.NotFoundError as e:
            if e.error == 'index_not_found_exception':
                rule_results['search_count'] = -1
            else:
                raise
        except (elasticsearch.NotFoundError, elasticsearch.RequestError):
            rule_results['search_count'] = -1

        alert_count = len(alerts.get(rule.id, []))
        if alert_count > 0:
            rule_results['alert_count'] = alert_count

        details[rule.id].update(rule_results)

        search_count = rule_results['search_count']
        if not alert_count and (hide_zero_counts and search_count == 0) or (hide_errors and search_count == -1):
            continue

        survey_results.append(rule_results)

    fields = ['rule_id', 'name', 'search_count', 'alert_count']
    table = Table.from_list(fields, survey_results)

    if len(survey_results) > 200:
        click.echo_via_pager(table)
    else:
        click.echo(table)

    if dump_file:
        os.makedirs(get_path('surveys'), exist_ok=True)
        with open(dump_file, 'w') as f:
            json.dump(details, f, indent=2, sort_keys=True)

    return survey_results


def get_detailed_search_results(client: Elasticsearch, rules, start_time, end_time, max_results=1000):
    """Get detailed search results for rules."""
    import kql
    from .misc import nested_get

    async_client = AsyncSearchClient(client)
    survey_results = {}

    def parse_unique_field_results(rule_type, unique_fields, search_results):
        parsed_results = defaultdict(lambda: defaultdict(int))
        hits = search_results['hits']['hits'] if rule_type != 'eql' else search_results.events
        for hit in hits:
            for field in unique_fields:
                match = nested_get(hit['_source'], field)
                match = ','.join(sorted(match)) if isinstance(match, list) else match
                parsed_results[field][match] += 1
        # if rule.type == eql, structure is different
        return {'results': parsed_results} if parsed_results else {}

    multi_search = []
    multi_search_rules = []
    async_searches = {}
    eql_searches = {}

    for rule in rules:
        if not rule.contents.get('query'):
            continue

        index = ','.join(rule.contents['index'])

        # dsl filter for date ranges for lucene and eql (kql is already dsl and so will mutate filter)
        range_dsl = {'query': {'bool': {'filter': []}}}
        add_range_to_dsl(range_dsl['query']['bool']['filter'], start_time, end_time)

        # prep for searches: msearch for kql | async search for lucene | eql client search for eql
        if rule.contents['language'] == 'kuery':
            multi_search_rules.append(rule)
            multi_search.append(json.dumps({'index': index}))
            kql_query = kql.to_dsl(rule.query)
            add_range_to_dsl(kql_query['bool'].setdefault('filter', []), start_time, end_time)
            body = {'query': kql_query, 'size': max_results, 'track_total_hits': True}
            multi_search.append(json.dumps(body))
        elif rule.contents['language'] == 'lucene':
            # wait for 0 to try and force async with no immediate results (not guaranteed)
            result = async_client.submit(body=range_dsl, q=rule.query, index=index, wait_for_completion_timeout=0,
                                         size=max_results, track_total_hits=True)
            if result['is_running'] is True:
                async_searches[rule] = result['id']
            else:
                survey_results[rule.id] = parse_unique_field_results(rule.type, rule.unique_fields, result['response'])
        elif rule.contents['language'] == 'eql':
            eql_body = {
                'index': index,
                'params': {'ignore_unavailable': 'true'},
                'body': {'query': rule.query, 'size': max_results, 'filter': range_dsl['query']}
            }
            eql_searches[rule] = eql_body

    # assemble search results
    multi_search_results = client.msearch('\n'.join(multi_search) + '\n')
    for index, result in enumerate(multi_search_results['responses']):
        try:
            rule = multi_search_rules[index]
            survey_results[rule.id] = parse_unique_field_results(rule.type, rule.unique_fields, result)
        except KeyError:
            survey_results[multi_search_rules[index].id] = {'error_retrieving_results': True}

    for rule, search_args in eql_searches.items():
        try:
            result = client.eql.search(**search_args)
            survey_results[rule.id] = parse_unique_field_results(rule.type, rule.unique_fields, result)
        except (elasticsearch.NotFoundError, elasticsearch.RequestError) as e:
            if e.error in ('index_not_found_exception', 'verification_exception'):
                survey_results[rule.id] = {'error_retrieving_results': True, 'error': e.info['error']['reason']}
            else:
                raise

    for rule, async_id in async_searches.items():
        result = async_client.get(async_id)['response']
        survey_results[rule.id] = parse_unique_field_results(rule.type, rule.unique_fields, result)

    return survey_results
