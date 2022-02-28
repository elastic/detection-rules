# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Schemas and dataclasses for GitHub releases."""

import dataclasses
import hashlib
import io
import json
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple
from zipfile import ZipFile

import click
import requests

from .schemas import definitions

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


def get_gh_release(repo: Repository, release_name: Optional[str] = None, tag_name: Optional[str] = None) -> GitRelease:
    """Get a list of GitHub releases by repo."""
    assert release_name or tag_name, 'Must specify a release_name or tag_name'

    releases = repo.get_releases()
    for release in releases:
        if release_name and release_name == release.title:
            return release
        elif tag_name and tag_name == release.tag_name:
            return release


def load_zipped_gh_assets_with_metadata(url: str) -> Tuple[str, dict]:
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


def load_json_gh_asset(url: str) -> dict:
    """Load and return the contents of a json asset file."""
    response = requests.get(url)
    response.raise_for_status()
    return response.json()


def download_gh_asset(url: str, path: str, overwrite=False):
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

    def __init__(self, token: Optional[str] = None):
        """Get an unauthenticated client, verified authenticated client, or a default client."""
        self.assert_github()
        self.client: Github = Github(token)
        self.unauthenticated_client = Github()
        self.__token = token
        self.__authenticated_client = None

    @classmethod
    def assert_github(cls):
        if not Github:
            raise ModuleNotFoundError('Missing PyGithub - try running `pip install -r requirements-dev.txt`')

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
    zipped_sha256: definitions.Sha256
    created_at: datetime = field(default_factory=datetime.utcnow)
    description: Optional[str] = None  # populated by GitHub release asset label


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
    description: str = None  # parsed from GitHub release metadata as: body


class ManifestManager:
    """Manifest handler for GitHub releases."""

    def __init__(self, repo: str = 'elastic/detection-rules', release_name: Optional[str] = None,
                 tag_name: Optional[str] = None, token: Optional[str] = None):
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
    def release_manifest_fl(self) -> io.BytesIO:
        return io.BytesIO(json.dumps(self.__release_manifest_dict, sort_keys=True).encode('utf-8'))

    def _create(self) -> ReleaseManifest:
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

    def _parse_release_metadata(self) -> dict:
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
    def load(cls, name: str, repo: str = 'elastic/detection-rules', token: Optional[str] = None) -> Optional[dict]:
        """Load a manifest."""
        gh_client = GithubClient(token)
        repo = gh_client.client.get_repo(repo)
        release = get_gh_release(repo, tag_name=name)

        for asset in release.get_assets():
            if asset.name == f'manifest-{name}.json':
                return load_json_gh_asset(asset.browser_download_url)

    @classmethod
    def load_all(cls, repo: str = 'elastic/detection-rules', token: Optional[str] = None
                 ) -> Tuple[Dict[str, dict], list]:
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
    def get_existing_asset_hashes(cls, repo: str = 'elastic/detection-rules', token: Optional[str] = None) -> dict:
        """Load all assets with their hashes, by release."""
        flat = {}
        consolidated, _ = cls.load_all(repo=repo, token=token)
        for release, data in consolidated.items():
            for asset in data['assets'].values():
                flat_release = flat[release] = {}
                for asset_name, asset_data in asset['entries'].items():
                    flat_release[asset_name] = asset_data['sha256']

        return flat

    def _get_enriched_assets_from_release(self) -> dict:
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
