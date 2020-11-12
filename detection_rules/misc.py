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
from pathlib import Path
from typing import Dict, Tuple
from zipfile import ZipFile

import click
import requests

from .utils import cached, get_path

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


def read_gh_asset(url) -> Tuple[str, dict]:
    """Download and unzip a GitHub asset."""
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
class ReleaseMetadata:

    assets: Dict[str, AssetManifestMetadata]
    assets_url: str
    author: str  # author[login]
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

    manifest_directory: Path = Path(__file__).resolve().parent.parent.joinpath('etc', 'release_manifests')

    def __init__(self, repo='elastic/detection-rules', release_name=None, tag_name=None):
        assets, release_meta = self._get_assets_from_release(repo, release_name, tag_name)
        self.assets: dict = assets
        self.release_meta: dict = release_meta
        self.release_manifest = self._create()

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
        release_manifest = ReleaseMetadata(**release_metadata)

        return release_manifest

    def _parse_release_metadata(self):
        """Parse relevant info from GitHub metadata for release manifest."""
        ignore = ['assets']
        manual_set_keys = ['author', 'description']
        keys = [f for f in list(ReleaseMetadata.__annotations__) if str(f) not in ignore + manual_set_keys]
        parsed = {k: self.release_meta[k] for k in keys}
        parsed.update(description=self.release_meta['body'], author=self.release_meta['author']['login'])
        return parsed

    def save(self):
        """Save manifest files."""
        path = self.manifest_directory.joinpath(f'{self.release_manifest.name}.json')
        with open(path, 'w') as f:
            json.dump(dataclasses.asdict(self.release_manifest), f, indent=2, sort_keys=True)
            click.echo(f'Manifest saved to: {path}')

    @classmethod
    def load(cls, name: str) -> dict:
        """Load a manifest entry."""
        name = f'{name}.json' if not name.endswith('.json') else name
        path = cls.manifest_directory.joinpath(name)
        with open(path, 'r') as f:
            return json.load(f)

    @classmethod
    def load_all(cls) -> dict:
        """Load a consolidated manifest."""
        consolidated = {}
        paths = cls.manifest_directory.glob('*.json')
        for path in paths:
            with open(path, 'r') as f:
                consolidated[Path(path).name] = json.load(f)

        return consolidated

    @classmethod
    def get_existing_asset_hashes(cls) -> dict:
        """Load all assets with their hashes, by release."""
        flat = {}
        consolidated = cls.load_all()
        for release, data in consolidated.items():
            for asset in data['assets'].values():
                for asset_name, asset_data in asset['entries'].items():
                    flat.setdefault(release, {})[asset_name] = asset_data['sha256']

        return flat

    @staticmethod
    def _get_assets_from_release(repo='elastic/detection-rules', release_name=None, tag_name=None):
        """Get assets and metadata from a GitHub release."""
        assert release_name or tag_name, 'Must specify a release_name or tag_name'

        base_url = f'https://api.github.com/repos/{repo}'

        if tag_name:
            release_url = f'{base_url}/releases/tags/{tag_name}'
            response = requests.get(release_url)
        else:
            release_url = f'{base_url}/releases'
            response = requests.get(release_url)

        response.raise_for_status()
        response = response.json()
        release_meta = response if isinstance(response, dict) else next((r for r in response
                                                                        if r['name'] == release_name), None)

        if not release_meta:
            raise ValueError(f'Unknown release: {release_name}')

        assets = {}
        for asset in release_meta['assets']:
            zipped_sha256, data = read_gh_asset(asset['browser_download_url'])
            asset.update(zipped_sha256=zipped_sha256)

            assets[asset['name']] = {
                'metadata': asset,
                'data': data
            }

        return assets, release_meta


class ClientError(click.ClickException):
    """Custom CLI error to format output or full debug stacktrace."""

    def __init__(self, message, original_error=None):
        super(ClientError, self).__init__(message)
        self.original_error = original_error

    def show(self, file=None, err=True):
        """Print the error to the console."""
        err = f' ({self.original_error})' if self.original_error else ''
        click.echo(f'{click.style(f"CLI Error{err}", fg="red", bold=True)}: {self.format_message()}',
                   err=err, file=file)


def client_error(message, exc: Exception = None, debug=None, ctx: click.Context = None, file=None, err=None):
    config_debug = True if ctx and ctx.ensure_object(dict) and ctx.obj.get('debug') is True else False
    debug = debug if debug is not None else config_debug

    if debug:
        click.echo(click.style('DEBUG: ', fg='yellow') + message, err=err, file=file)
        raise
    else:
        raise ClientError(message, original_error=type(exc).__name__ if exc else None)


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
    config_file = get_path('.detection-rules-cfg.json')
    config = {}

    if os.path.exists(config_file):
        with open(config_file) as f:
            config = json.load(f)

        click.secho('Loaded config file: {}'.format(config_file), fg='yellow')

    return config


def getdefault(name):
    """Callback function for `default` to get an environment variable."""
    envvar = f"DR_{name.upper()}"
    config = parse_config()
    return lambda: os.environ.get(envvar, config.get(name))
