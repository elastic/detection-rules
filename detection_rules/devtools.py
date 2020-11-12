# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""CLI commands for internal detection_rules dev team."""
import glob
import hashlib
import io
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import click
from eql import load_dump

from . import rule_loader
from .main import root
from .misc import Manifest, PYTHON_LICENSE, client_error, getdefault
from .packaging import PACKAGE_FILE, Package, manage_versions, RELEASE_DIR
from .rule import Rule
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


@dev_group.group('gh-release')
def gh_release_group():
    """Commands to manage GitHub releases."""


@gh_release_group.command('create-ml')
@click.argument('directory', type=click.Path(dir_okay=True, file_okay=False))
@click.option('--gh-token', '-t', default=getdefault('gh_token'))
@click.option('--repo', '-r', default='elastic/detection-rules', help='GitHub owner/repo')
@click.option('--release-name', '-n', required=True, help='Name of release')
@click.option('--description', '-d', help='Description of release to append to default message')
@click.pass_context
def create_ml_release(ctx, directory, gh_token, repo, release_name, description):
    """Create a GitHub release."""
    import re
    import requests

    # ML-DGA-20201129-25
    pattern = r'^(ML-DGA|ML-experimental-detections)-20\d\d[0-1]\d[0-3]\d-\d+$'
    assert re.match(pattern, release_name), f'release name must match pattern: {pattern}'
    assert Path(directory).name == release_name, f'directory name must match release name: {release_name}'

    try:
        from github import Github
    except ImportError as e:
        Github = None  # noqa: N806  # for type hinting
        client_error('Missing PyGithub - try running `pip install -r requirements-dev.txt`', e)

    gh_token = gh_token or click.prompt('GitHub token', hide_input=True)
    client = Github(gh_token)
    gh_repo = client.get_repo(repo)

    # validate tag name is increment by 1
    name_parts = release_name.rsplit('-')
    name_prefix = '-'.join(name_parts[:2])
    version = int(name_parts[-1])
    releases = gh_repo.get_releases()
    max_ver = max([int(r.raw_data['name'].split('-')[-1]) for r in releases
                   if r.raw_data['name'].startswith(name_prefix)], default=0)

    if version != (max_ver + 1):
        client_error(f'Last release version was {max_ver}. Release name should end with version: {max_ver + 1}')

    # validate files
    if name_prefix == 'ML-DGA':
        zipped_bundle, description_str = ctx.invoke(validate_ml_dga_asset, directory=directory)
    else:
        zipped_bundle, description_str = ctx.invoke(validate_ml_detections_asset, directory=directory)

    click.confirm('Validation passed, verify output. Continue?')

    if description:
        description_str = f'{description_str}\n\n----\n\n{description}'

    release = gh_repo.create_git_release(name=release_name, tag=release_name, message=description_str)
    zip_name = Path(zipped_bundle).name

    # add zipped bundle as an asset to the release
    with open(zipped_bundle, 'rb') as zipped_fo:
        headers = {'content-type': 'application/zip'}
        suffix = '{?name,label}'
        url = release.upload_url.replace(suffix, f'?name={zip_name}&label={zip_name}')
        r = requests.post(url, auth=('', gh_token), data=zipped_fo.read(), headers=headers)
        r.raise_for_status()

    # create manifest entry
    manifest = Manifest(repo, tag_name=release_name)
    manifest.save()

    return release


@gh_release_group.command('validate-ml-dga-asset')
@click.argument('directory', type=click.Path(exists=True, file_okay=False))
def validate_ml_dga_asset(directory):
    """"Validate and prep an ML DGA bundle for release."""
    from .eswrap import expected_ml_dga_patterns

    now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

    files = list(Path(directory).glob('*'))
    if len(files) > 5:
        client_error('Too many files, expected 5')

    click.secho('[*] validated expected number of files', fg='green')

    # backup files - will re-save sorted to have deterministic hash
    backup_path = Path(directory).resolve().parent.joinpath(f'backups-{Path(directory).name}-{now.replace(":", "-")}')
    shutil.copytree(directory, backup_path)

    # validate file names and json and load
    loaded_contents = {}
    for name, pattern in expected_ml_dga_patterns.items():
        path = list(Path(directory).glob(pattern))
        match_count = len(path)
        if match_count != 1:
            client_error(f'Expected filename pattern "{pattern}" for "{name}": {match_count} matches detected')

        file_path = path[0]
        try:
            with open(file_path, 'r') as f:
                contents = json.dumps(json.load(f), sort_keys=True)
                loaded_contents[name] = {'contents': contents, 'filename': file_path}

                sha256 = hashlib.sha256(contents.encode('utf-8')).hexdigest()
                click.secho(f'     - sha256: {sha256} - {name}')

            # re-save sorted
            with open(file_path, 'w') as f:
                f.write(contents)
        except json.JSONDecodeError as e:
            client_error(f'Invalid JSON in {file_path} file', e)

    model_filename = Path(loaded_contents['model']['filename']).name
    model_name, _ = model_filename.rsplit('_', maxsplit=1)

    click.secho('[*] re-saved all files with keys sorted for deterministic hashing', fg='green')
    click.secho(f'    [+] backups saved to: {backup_path}')
    click.secho('[*] validated expected naming patterns for all files', fg='green')
    click.secho('[*] validated json formatting of all files', fg='green')

    # check manifest for existing things
    existing_sha = False
    existing_model_name = False
    model_hash = hashlib.sha256(loaded_contents['model']['contents'].encode('utf-8')).hexdigest()
    manifest_hashes = Manifest.get_existing_asset_hashes()
    for release, file_data in manifest_hashes.items():
        for file_name, sha in file_data.items():
            if model_hash == sha:
                existing_sha = True
                click.secho(f'[!] hash for model file: "{loaded_contents["model"]["filename"]}" matches: '
                            f'{release} -> {file_name} -> {sha}', fg='yellow')

            if model_filename == file_name:
                existing_model_name = True
                click.secho(f'[!] name for model file: "{loaded_contents["model"]["filename"]}" matches: '
                            f'{release} -> {file_name} -> {file_name}', fg='yellow')

    if not existing_sha:
        click.secho(f'[+] validated no existing models matched hashes for: '
                    f'{loaded_contents["model"]["filename"]}', fg='green')

    if not existing_model_name:
        click.secho(f'[+] validated no existing models matched names for: '
                    f'{loaded_contents["model"]["filename"]}', fg='green')

    # save zip
    zip_name_no_ext = Path(directory).resolve()
    zip_name = f'{zip_name_no_ext}.zip'
    shutil.make_archive(str(zip_name_no_ext), 'zip', root_dir=zip_name_no_ext.parent, base_dir=zip_name_no_ext.name)
    click.secho(f'[+] zipped folder saved to {zip_name} for release', fg='green')

    click.secho(f'[!] run `setup-dga-model -d {directory}` to test this on a live stack before releasing!', fg='yellow')

    description = {
        'model_name': model_name + '\n\n----\n\n',
        'date': now,
        'model_sha256': model_hash
    }
    description_str = '\n'.join([f'{k}: {v}' for k, v in description.items()])
    click.echo()
    click.echo(f'[*] description to paste with release:\n\n{description_str}\n')

    return zip_name, description_str


@gh_release_group.command('validate-ml-detections-asset')
@click.argument('directory', type=click.Path(exists=True, file_okay=False))
def validate_ml_detections_asset(directory):
    """Validate and prep ML detection rules and jobs before release."""
    import pytoml

    now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

    job_paths = list(Path(directory).glob('*.json'))
    rule_paths = list(Path(directory).glob('*.toml'))
    job_count = len(job_paths)
    rule_count = len(rule_paths)

    for job in job_paths:
        try:
            with open(job, 'r') as f:
                j = json.load(f)
                assert j.get('name'), click.style(f'[!] job file "{job}" missing: name', fg='red')
                assert j.get('type'), click.style(f'[!] job file "{job}" missing: type', fg='red')
                assert j.get('body'), click.style(f'[!] job file "{job}" missing: body', fg='red')
        except json.JSONDecodeError as e:
            client_error(f'Invalid JSON in {job} file', e)

    click.secho(f'[*] validated json formatting and required fields in {job_count} job files', fg='green')

    for rule in rule_paths:
        with open(rule, 'r') as f:
            try:
                pytoml.load(f)
            except pytoml.TomlError as e:
                client_error(f'[!] invalid rule toml for: {rule}', e)

    click.secho(f'[*] validated toml formatting for {rule_count} rule files', fg='green')

    # save zip
    zip_name_no_ext = Path(directory).resolve()
    zip_name = f'{zip_name_no_ext}.zip'
    shutil.make_archive(str(zip_name_no_ext), 'zip', root_dir=zip_name_no_ext.parent, base_dir=zip_name_no_ext.name)
    click.secho(f'[+] zipped folder saved to {zip_name} for release', fg='green')

    click.secho('[!] run `kibana upload-rule` to test rules on a live stack before releasing!', fg='green')
    click.secho('[!] run `es upload-ml-job` to test jobs on a live stack before releasing!', fg='green')

    description = {
        'Experimental ML rules': rule_count,
        'Experimental ML jobs': str(job_count) + '\n\n----\n\n',
        'DGA release': '<add link to DGA release these detections were built on>',
        'date': now
    }
    description_str = '\n'.join([f'{k}: {v}' for k, v in description.items()])
    click.echo()
    click.echo(f'description to paste with release:\n\n{description_str}\n')

    return zip_name, description_str
