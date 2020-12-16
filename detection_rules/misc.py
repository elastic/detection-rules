# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Misc support."""
import hashlib
import io
import json
import os
import re
import shutil
import time
import uuid
import dataclasses

from dataclasses import dataclass, field
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Dict, Tuple
from zipfile import ZipFile

import click
import requests

# this is primarily for type hinting - all use of the github client should come from GithubClient class
try:
    from github import Github
    from github.Repository import Repository
    from github.GitRelease import GitRelease
    from github.GitReleaseAsset import GitReleaseAsset
except ImportError:
    # for type hinting
    Github = None  # noqa: N806
    Repository = None  # noqa: N806
    GitRelease = None  # noqa: N806
    GitReleaseAsset = None  # noqa: N806

from .utils import ROOT_DIR, add_params, cached

_CONFIG = {}

LICENSE_HEADER = """
Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
or more contributor license agreements. Licensed under the Elastic License;
you may not use this file except in compliance with the Elastic License.
""".strip()

LICENSE_LINES = LICENSE_HEADER.splitlines()
PYTHON_LICENSE = "\n".join("# " + line for line in LICENSE_LINES)
JS_LICENSE = """
/*
{}
 */
""".strip().format("\n".join(' * ' + line for line in LICENSE_LINES))


def get_gh_release(repo: Repository, release_name=None, tag_name=None) -> GitRelease:
    """Get a list of GitHub releases by repo."""
    assert release_name or tag_name, 'Must specify a release_name or tag_name'

    releases = repo.get_releases()
    release = next((r for r in releases
                    if (release_name and release_name == r.title) or (tag_name and tag_name == r.tag_name)), None)

    return release


def upload_gh_release_asset(token, asset: bytes, asset_name, repo=None, content_type='application/zip',
                            release_name=None, tag_name=None, upload_url=None):
    """Save a Github relase asset."""
    if not upload_url:
        assert repo, 'You must provide a repo name if not providing an upload_url'

        release = get_gh_release(repo, release_name, tag_name)
        upload_url = release['upload_url']
        suffix = '{?name,label}'
        upload_url = upload_url.replace(suffix, f'?name={asset_name}&label={asset_name}')

    headers = {'content-type': content_type}
    r = requests.post(upload_url, auth=('', token), data=asset, headers=headers)
    r.raise_for_status()
    click.echo(f'Uploaded {asset_name} to release: {r.json()["url"]}')


def load_zipped_gh_assets_with_metadata(url) -> Tuple[str, dict]:
    """Download and unzip a GitHub assets."""
    response = requests.get(url)
    zipped_asset = ZipFile(io.BytesIO(response.content))
    zipped_sha256 = hashlib.sha256(response.content).hexdigest()

    assets = {}
    for zipped in zipped_asset.filelist:
        if zipped.is_dir():
            continue

        contents = zipped_asset.read(zipped.filename)
        sha256 = hashlib.sha256(contents).hexdigest()

        assets[zipped.filename] = {
            'contents': contents,
            'metadata': {
                'compress_size': zipped.compress_size,
                # zipfile provides only a 6 tuple datetime; -1 means DST is unknown;  0's set tm_wday and tm_yday
                'created_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', zipped.date_time + (0, 0, -1)),
                'sha256': sha256,
                'size': zipped.file_size,
            }
        }

    return zipped_sha256, assets


def load_json_gh_asset(url) -> dict:
    """Load and return the contents of a json asset file."""
    response = requests.get(url)
    response.raise_for_status()
    return response.json()


def download_gh_asset(url, path, overwrite=False):
    """Download and unzip a GitHub asset."""
    zipped = requests.get(url)
    z = ZipFile(io.BytesIO(zipped.content))

    Path(path).mkdir(exist_ok=True)
    if overwrite:
        shutil.rmtree(path, ignore_errors=True)

    z.extractall(path)
    click.echo(f'files saved to {path}')

    z.close()


class GithubClient:
    """GitHub client wrapper."""

    def __init__(self, token=None):
        """Get an unauthenticated client, verified authenticated client, or a default client."""
        if not Github:
            raise ModuleNotFoundError('Missing PyGithub - try running `pip install -r requirements-dev.txt`')

        self.client: Github = Github(token)
        self.unauthenticated_client = Github()
        self.__token = token
        self.__authenticated_client = None

    @property
    def authenticated_client(self) -> Github:
        if not self.__token:
            raise ValueError('Token not defined! Re-instantiate with a token or use add_token method')
        if not self.__authenticated_client:
            self.__authenticated_client = Github(self.__token)
        return self.__authenticated_client

    def add_token(self, token):
        self.__token = token


@dataclass
class AssetManifestEntry:

    compress_size: int
    created_at: datetime
    name: str
    sha256: str
    size: int


@dataclass
class AssetManifestMetadata:

    relative_url: str
    entries: Dict[str, AssetManifestEntry]
    zipped_sha256: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    description: str = None  # label


@dataclass
class ReleaseManifest:

    assets: Dict[str, AssetManifestMetadata]
    assets_url: str
    author: str  # parsed from GitHub release metadata as: author[login]
    created_at: str
    html_url: str
    id: int
    name: str
    published_at: str
    url: str
    zipball_url: str
    tag_name: str = None
    description: str = None  # body


class Manifest:
    """Manifest handler for GitHub releases."""

    def __init__(self, repo: str = 'elastic/detection-rules', release_name=None, tag_name=None, token=None):
        self.repo_name = repo
        self.release_name = release_name
        self.tag_name = tag_name
        self.gh_client = GithubClient(token)
        self.has_token = token is not None

        self.repo: Repository = self.gh_client.client.get_repo(repo)
        self.release: GitRelease = get_gh_release(self.repo, release_name, tag_name)

        if not self.release:
            raise ValueError(f'No release found for {tag_name or release_name}')

        if not self.release_name:
            self.release_name = self.release.title

        self.manifest_name = f'manifest-{self.release_name}.json'
        self.assets: dict = self._get_enriched_assets_from_release()
        self.release_manifest = self._create()
        self.__release_manifest_dict = dataclasses.asdict(self.release_manifest)
        self.manifest_size = len(json.dumps(self.__release_manifest_dict))

    @property
    def release_manifest_fl(self):
        return io.BytesIO(json.dumps(self.__release_manifest_dict, sort_keys=True).encode('utf-8'))

    def _create(self):
        """Create the manifest from GitHub asset metadata and file contents."""
        assets = {}
        for asset_name, asset_data in self.assets.items():
            entries = {}
            data = asset_data['data']
            metadata = asset_data['metadata']

            for file_name, file_data in data.items():
                file_metadata = file_data['metadata']

                name = Path(file_name).name
                file_metadata.update(name=name)

                entry = AssetManifestEntry(**file_metadata)
                entries[name] = entry

            assets[asset_name] = AssetManifestMetadata(metadata['browser_download_url'], entries,
                                                       metadata['zipped_sha256'], metadata['created_at'],
                                                       metadata['label'])

        release_metadata = self._parse_release_metadata()
        release_metadata.update(assets=assets)
        release_manifest = ReleaseManifest(**release_metadata)

        return release_manifest

    def _parse_release_metadata(self):
        """Parse relevant info from GitHub metadata for release manifest."""
        ignore = ['assets']
        manual_set_keys = ['author', 'description']
        keys = [f.name for f in dataclasses.fields(ReleaseManifest) if f.name not in ignore + manual_set_keys]
        parsed = {k: self.release.raw_data[k] for k in keys}
        parsed.update(description=self.release.raw_data['body'], author=self.release.raw_data['author']['login'])
        return parsed

    def save(self) -> GitReleaseAsset:
        """Save manifest files."""
        if not self.has_token:
            raise ValueError('You must provide a token to save a manifest to a GitHub release')

        asset = self.release.upload_asset_from_memory(self.release_manifest_fl,
                                                      self.manifest_size,
                                                      self.manifest_name)
        click.echo(f'Manifest saved as {self.manifest_name} to {self.release.html_url}')
        return asset

    @classmethod
    def load(cls, name: str, repo: str = 'elastic/detection-rules', token=None) -> dict:
        """Load a manifest."""
        gh_client = GithubClient(token)
        repo = gh_client.client.get_repo(repo)
        release = get_gh_release(repo, tag_name=name)
        asset = next((a for a in release.get_assets() if a.name == f'manifest-{name}.json'), None)

        if asset is not None:
            return load_json_gh_asset(asset.browser_download_url)

    @classmethod
    def load_all(cls, repo: str = 'elastic/detection-rules', token=None) -> Tuple[Dict[str, dict], list]:
        """Load a consolidated manifest."""
        gh_client = GithubClient(token)
        repo = gh_client.client.get_repo(repo)

        consolidated = {}
        missing = set()
        for release in repo.get_releases():
            name = release.tag_name
            asset = next((a for a in release.get_assets() if a.name == f'manifest-{name}.json'), None)
            if not asset:
                missing.add(name)
            else:
                consolidated[name] = load_json_gh_asset(asset.browser_download_url)

        return consolidated, list(missing)

    @classmethod
    def get_existing_asset_hashes(cls, repo: str = 'elastic/detection-rules', token=None) -> dict:
        """Load all assets with their hashes, by release."""
        flat = {}
        consolidated, _ = cls.load_all(repo=repo, token=token)
        for release, data in consolidated.items():
            for asset in data['assets'].values():
                flat_release = flat[release] = {}
                for asset_name, asset_data in asset['entries'].items():
                    flat_release[asset_name] = asset_data['sha256']

        return flat

    def _get_enriched_assets_from_release(self):
        """Get assets and metadata from a GitHub release."""
        assets = {}
        for asset in [a.raw_data for a in self.release.get_assets()]:
            zipped_sha256, data = load_zipped_gh_assets_with_metadata(asset['browser_download_url'])
            asset.update(zipped_sha256=zipped_sha256)

            assets[asset['name']] = {
                'metadata': asset,
                'data': data
            }

        return assets


def get_ml_model_manifests_by_model_id(repo: str = 'elastic/detection-rules') -> Dict[str, ReleaseManifest]:
    """Load all ML DGA model release manifests by model id."""
    manifests, _ = Manifest.load_all(repo=repo)
    model_manifests = {}

    for manifest_name, manifest in manifests.items():
        for asset_name, asset in manifest['assets'].items():
            for entry_name, entry_data in asset['entries'].items():
                if entry_name.startswith('dga') and entry_name.endswith('model.json'):
                    model_id, _ = entry_name.rsplit('_', 1)
                    model_manifests[model_id] = ReleaseManifest(**manifest)
                    break

    return model_manifests


class ClientError(click.ClickException):
    """Custom CLI error to format output or full debug stacktrace."""

    def __init__(self, message, original_error=None):
        super(ClientError, self).__init__(message)
        self.original_error = original_error
        self.original_error_type = type(original_error).__name__ if original_error else ''

    def show(self, file=None, err=True):
        """Print the error to the console."""
        err = f' {self.original_error_type}' if self.original_error else ''
        msg = f'{click.style(f"CLI Error{self.original_error_type}", fg="red", bold=True)}: {self.format_message()}'
        click.echo(msg, err=err, file=file)


def client_error(message, exc: Exception = None, debug=None, ctx: click.Context = None, file=None, err=None):
    config_debug = True if ctx and ctx.ensure_object(dict) and ctx.obj.get('debug') is True else False
    debug = debug if debug is not None else config_debug

    if debug:
        click.echo(click.style('DEBUG: ', fg='yellow') + message, err=err, file=file)
        raise
    else:
        raise ClientError(message, original_error=exc)


def nested_get(_dict, dot_key, default=None):
    """Get a nested field from a nested dict with dot notation."""
    if _dict is None or dot_key is None:
        return default
    elif '.' in dot_key and isinstance(_dict, dict):
        dot_key = dot_key.split('.')
        this_key = dot_key.pop(0)
        return nested_get(_dict.get(this_key, default), '.'.join(dot_key), default)
    else:
        return _dict.get(dot_key, default)


def nested_set(_dict, dot_key, value):
    """Set a nested field from a a key in dot notation."""
    keys = dot_key.split('.')
    for key in keys[:-1]:
        _dict = _dict.setdefault(key, {})

    if isinstance(_dict, dict):
        _dict[keys[-1]] = value
    else:
        raise ValueError('dict cannot set a value to a non-dict for {}'.format(dot_key))


def schema_prompt(name, value=None, required=False, **options):
    """Interactively prompt based on schema requirements."""
    name = str(name)
    field_type = options.get('type')
    pattern = options.get('pattern')
    enum = options.get('enum', [])
    minimum = options.get('minimum')
    maximum = options.get('maximum')
    min_item = options.get('min_items', 0)
    max_items = options.get('max_items', 9999)

    default = options.get('default')
    if default is not None and str(default).lower() in ('true', 'false'):
        default = str(default).lower()

    if 'date' in name:
        default = time.strftime('%Y/%m/%d')

    if name == 'rule_id':
        default = str(uuid.uuid4())

    if len(enum) == 1 and required and field_type != "array":
        return enum[0]

    def _check_type(_val):
        if field_type in ('number', 'integer') and not str(_val).isdigit():
            print('Number expected but got: {}'.format(_val))
            return False
        if pattern and (not re.match(pattern, _val) or len(re.match(pattern, _val).group(0)) != len(_val)):
            print('{} did not match pattern: {}!'.format(_val, pattern))
            return False
        if enum and _val not in enum:
            print('{} not in valid options: {}'.format(_val, ', '.join(enum)))
            return False
        if minimum and (type(_val) == int and int(_val) < minimum):
            print('{} is less than the minimum: {}'.format(str(_val), str(minimum)))
            return False
        if maximum and (type(_val) == int and int(_val) > maximum):
            print('{} is greater than the maximum: {}'.format(str(_val), str(maximum)))
            return False
        if field_type == 'boolean' and _val.lower() not in ('true', 'false'):
            print('Boolean expected but got: {}'.format(str(_val)))
            return False
        return True

    def _convert_type(_val):
        if field_type == 'boolean' and not type(_val) == bool:
            _val = True if _val.lower() == 'true' else False
        return int(_val) if field_type in ('number', 'integer') else _val

    prompt = '{name}{default}{required}{multi}'.format(
        name=name,
        default=' [{}] ("n/a" to leave blank) '.format(default) if default else '',
        required=' (required) ' if required else '',
        multi=' (multi, comma separated) ' if field_type == 'array' else '').strip() + ': '

    while True:
        result = value or input(prompt) or default
        if result == 'n/a':
            result = None

        if not result:
            if required:
                value = None
                continue
            else:
                return

        if field_type == 'array':
            result_list = result.split(',')

            if not (min_item < len(result_list) < max_items):
                if required:
                    value = None
                    break
                else:
                    return []

            for value in result_list:
                if not _check_type(value):
                    if required:
                        value = None
                        break
                    else:
                        return []
            return [_convert_type(r) for r in result_list]
        else:
            if _check_type(result):
                return _convert_type(result)
            elif required:
                value = None
                continue
            return


def get_kibana_rules_map(branch='master'):
    """Get list of available rules from the Kibana repo and return a list of URLs."""
    # ensure branch exists
    r = requests.get(f'https://api.github.com/repos/elastic/kibana/branches/{branch}')
    r.raise_for_status()

    url = ('https://api.github.com/repos/elastic/kibana/contents/x-pack/{legacy}plugins/{app}/server/lib/'
           'detection_engine/rules/prepackaged_rules?ref={branch}')

    gh_rules = requests.get(url.format(legacy='', app='security_solution', branch=branch)).json()

    # pre-7.9 app was siem
    if isinstance(gh_rules, dict) and gh_rules.get('message', '') == 'Not Found':
        gh_rules = requests.get(url.format(legacy='', app='siem', branch=branch)).json()

    # pre-7.8 the siem was under the legacy directory
    if isinstance(gh_rules, dict) and gh_rules.get('message', '') == 'Not Found':
        gh_rules = requests.get(url.format(legacy='legacy/', app='siem', branch=branch)).json()

    if isinstance(gh_rules, dict) and gh_rules.get('message', '') == 'Not Found':
        raise ValueError(f'rules directory does not exist for branch: {branch}')

    return {os.path.splitext(r['name'])[0]: r['download_url'] for r in gh_rules if r['name'].endswith('.json')}


def get_kibana_rules(*rule_paths, branch='master', verbose=True, threads=50):
    """Retrieve prepackaged rules from kibana repo."""
    from multiprocessing.pool import ThreadPool

    kibana_rules = {}

    if verbose:
        thread_use = f' using {threads} threads' if threads > 1 else ''
        click.echo(f'Downloading rules from {branch} branch in kibana repo{thread_use} ...')

    rule_paths = [os.path.splitext(os.path.basename(p))[0] for p in rule_paths]
    rules_mapping = [(n, u) for n, u in get_kibana_rules_map(branch).items() if n in rule_paths] if rule_paths else \
        get_kibana_rules_map(branch).items()

    def download_worker(rule_info):
        n, u = rule_info
        kibana_rules[n] = requests.get(u).json()

    pool = ThreadPool(processes=threads)
    pool.map(download_worker, rules_mapping)
    pool.close()
    pool.join()

    return kibana_rules


@cached
def parse_config():
    """Parse a default config file."""
    config_file = ROOT_DIR / '.detection-rules-cfg.json'
    config = {}

    if config_file.exists():
        with open(config_file) as f:
            config = json.load(f)

        click.secho('Loaded config file: {}'.format(config_file), fg='yellow')

    return config


def getdefault(name):
    """Callback function for `default` to get an environment variable."""
    envvar = f"DR_{name.upper()}"
    config = parse_config()
    return lambda: os.environ.get(envvar, config.get(name))


client_options = {
    'kibana': {
        'cloud_id': click.Option(['--cloud-id'], default=getdefault('cloud_id')),
        'kibana_cookie': click.Option(['--kibana-cookie', '-kc'], default=getdefault('kibana_cookie'),
                                      help='Cookie from an authed session'),
        'kibana_password': click.Option(['--kibana-password', '-kp'], default=getdefault('kibana_password')),
        'kibana_url': click.Option(['--kibana-url'], default=getdefault('kibana_url')),
        'kibana_user': click.Option(['--kibana-user', '-ku'], default=getdefault('kibana_user')),
        'space': click.Option(['--space'], default=None, help='Kibana space')
    },
    'elasticsearch': {
        'cloud_id': click.Option(['--cloud-id'], default=getdefault("cloud_id")),
        'elasticsearch_url': click.Option(['--elasticsearch-url'], default=getdefault("elasticsearch_url")),
        'es_user': click.Option(['--es-user', '-eu'], default=getdefault("es_user")),
        'es_password': click.Option(['--es-password', '-ep'], default=getdefault("es_password")),
        'timeout': click.Option(['--timeout', '-et'], default=60, help='Timeout for elasticsearch client')
    }
}
kibana_options = list(client_options['kibana'].values())
elasticsearch_options = list(client_options['elasticsearch'].values())


def add_client(*client_type, add_to_ctx=True):
    """Wrapper to add authed client."""
    from elasticsearch import Elasticsearch, ElasticsearchException
    from kibana import Kibana
    from .eswrap import get_elasticsearch_client
    from .kbwrap import get_kibana_client

    def _wrapper(func):
        client_ops_dict = {}
        client_ops_keys = {}
        for c_type in client_type:
            ops = client_options.get(c_type)
            client_ops_dict.update(ops)
            client_ops_keys[c_type] = list(ops)

        if not client_ops_dict:
            raise ValueError(f'Unknown client: {client_type} in {func.__name__}')

        client_ops = list(client_ops_dict.values())

        @wraps(func)
        @add_params(*client_ops)
        def _wrapped(*args, **kwargs):
            ctx: click.Context = next((a for a in args if isinstance(a, click.Context)), None)
            es_client_args = {k: kwargs.pop(k, None) for k in client_ops_keys.get('elasticsearch', [])}
            #                                      shared args like cloud_id
            kibana_client_args = {k: kwargs.pop(k, es_client_args.get(k)) for k in client_ops_keys.get('kibana', [])}

            if 'elasticsearch' in client_type:
                # for nested ctx invocation, no need to re-auth if an existing client is already passed
                elasticsearch_client: Elasticsearch = kwargs.get('elasticsearch_client')
                try:
                    if elasticsearch_client and isinstance(elasticsearch_client, Elasticsearch) and \
                            elasticsearch_client.info():
                        pass
                    else:
                        elasticsearch_client = get_elasticsearch_client(use_ssl=True, **es_client_args)
                except ElasticsearchException:
                    elasticsearch_client = get_elasticsearch_client(use_ssl=True, **es_client_args)

                kwargs['elasticsearch_client'] = elasticsearch_client
                if ctx and add_to_ctx:
                    ctx.obj['es'] = elasticsearch_client

            if 'kibana' in client_type:
                # for nested ctx invocation, no need to re-auth if an existing client is already passed
                kibana_client: Kibana = kwargs.get('kibana_client')
                try:
                    with kibana_client:
                        if kibana_client and isinstance(kibana_client, Kibana) and kibana_client.version:
                            pass
                        else:
                            kibana_client = get_kibana_client(**kibana_client_args)
                except (requests.HTTPError, AttributeError):
                    kibana_client = get_kibana_client(**kibana_client_args)

                kwargs['kibana_client'] = kibana_client
                if ctx and add_to_ctx:
                    ctx.obj['kibana'] = kibana_client

            return func(*args, **kwargs)

        return _wrapped

    return _wrapper
