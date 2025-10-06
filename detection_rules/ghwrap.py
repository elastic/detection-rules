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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from zipfile import ZipFile

import click
import requests
from github import Github
from github.GitRelease import GitRelease
from github.GitReleaseAsset import GitReleaseAsset
from github.Repository import Repository
from requests import Response

from .schemas import definitions


def get_gh_release(repo: Repository, release_name: str | None = None, tag_name: str | None = None) -> GitRelease | None:
    """Get a list of GitHub releases by repo."""
    if not release_name and not tag_name:
        raise ValueError("Must specify a release_name or tag_name")

    releases = repo.get_releases()
    for release in releases:
        if (release_name and release_name == release.title) or (tag_name and tag_name == release.tag_name):
            return release
    return None


def load_zipped_gh_assets_with_metadata(url: str) -> tuple[str, dict[str, Any]]:
    """Download and unzip a GitHub assets."""
    response = requests.get(url, timeout=30)
    zipped_asset = ZipFile(io.BytesIO(response.content))
    zipped_sha256 = hashlib.sha256(response.content).hexdigest()

    assets: dict[str, Any] = {}
    for zipped in zipped_asset.filelist:
        if zipped.is_dir():
            continue

        contents = zipped_asset.read(zipped.filename)
        sha256 = hashlib.sha256(contents).hexdigest()

        assets[zipped.filename] = {
            "contents": contents,
            "metadata": {
                "compress_size": zipped.compress_size,
                # zipfile provides only a 6 tuple datetime; -1 means DST is unknown;  0's set tm_wday and tm_yday
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", (*zipped.date_time, 0, 0, -1)),
                "sha256": sha256,
                "size": zipped.file_size,
            },
        }

    return zipped_sha256, assets


def load_json_gh_asset(url: str) -> dict[str, Any]:
    """Load and return the contents of a json asset file."""
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.json()


def download_gh_asset(url: str, path: str, overwrite: bool = False) -> None:
    """Download and unzip a GitHub asset."""
    zipped = requests.get(url, timeout=30)
    z = ZipFile(io.BytesIO(zipped.content))

    Path(path).mkdir(exist_ok=True)
    if overwrite:
        shutil.rmtree(path, ignore_errors=True)

    z.extractall(path)
    click.echo(f"files saved to {path}")

    z.close()


def update_gist(  # noqa: PLR0913
    token: str,
    file_map: dict[Path, str],
    description: str,
    gist_id: str,
    public: bool = False,
    pre_purge: bool = False,
) -> Response:
    """Update existing gist."""
    url = f"https://api.github.com/gists/{gist_id}"
    headers = {"accept": "application/vnd.github.v3+json", "Authorization": f"token {token}"}
    body: dict[str, Any] = {
        "description": description,
        "files": {},  # {path.name: {'content': contents} for path, contents in file_map.items()},
        "public": public,
    }

    if pre_purge:
        # retrieve all existing file names which are not in the file_map and overwrite them to empty to delete files
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        files = list(data["files"])
        body["files"] = {file: {} for file in files if file not in file_map}
        response = requests.patch(url, headers=headers, json=body, timeout=30)
        response.raise_for_status()

    body["files"] = {path.name: {"content": contents} for path, contents in file_map.items()}
    response = requests.patch(url, headers=headers, json=body, timeout=30)
    response.raise_for_status()
    return response


class GithubClient:
    """GitHub client wrapper."""

    def __init__(self, token: str | None = None) -> None:
        """Get an unauthenticated client, verified authenticated client, or a default client."""
        self.assert_github()
        self.client = Github(token)
        self.unauthenticated_client = Github()
        self.__token = token
        self.__authenticated_client = None

    @classmethod
    def assert_github(cls) -> None:
        if not Github:
            raise ModuleNotFoundError("Missing PyGithub - try running `pip3 install .[dev]`")

    @property
    def authenticated_client(self) -> Github:
        if not self.__token:
            raise ValueError("Token not defined! Re-instantiate with a token or use add_token method")
        if not self.__authenticated_client:
            self.__authenticated_client = Github(self.__token)
        return self.__authenticated_client

    def add_token(self, token: str) -> None:
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
    entries: dict[str, AssetManifestEntry]
    zipped_sha256: definitions.Sha256
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    description: str | None = None  # populated by GitHub release asset label


@dataclass
class ReleaseManifest:
    assets: dict[str, AssetManifestMetadata]
    assets_url: str
    author: str  # parsed from GitHub release metadata as: author[login]
    created_at: str
    html_url: str
    id: int
    name: str
    published_at: str
    url: str
    zipball_url: str
    tag_name: str | None = None
    description: str | None = None  # parsed from GitHub release metadata as: body


class ManifestManager:
    """Manifest handler for GitHub releases."""

    def __init__(
        self,
        repo: str = "elastic/detection-rules",
        release_name: str | None = None,
        tag_name: str | None = None,
        token: str | None = None,
    ) -> None:
        self.repo_name = repo
        self.release_name = release_name
        self.tag_name = tag_name
        self.gh_client = GithubClient(token)
        self.has_token = token is not None

        self.repo: Repository = self.gh_client.client.get_repo(repo)
        release = get_gh_release(self.repo, release_name, tag_name)
        if not release:
            raise ValueError("No release info found")
        self.release = release

        if not self.release:
            raise ValueError(f"No release found for {tag_name or release_name}")

        if not self.release_name:
            self.release_name = self.release.title

        self.manifest_name = f"manifest-{self.release_name}.json"
        self.assets = self._get_enriched_assets_from_release()
        self.release_manifest = self._create()
        self.__release_manifest_dict = dataclasses.asdict(self.release_manifest)
        self.manifest_size = len(json.dumps(self.__release_manifest_dict))

    @property
    def release_manifest_fl(self) -> io.BytesIO:
        return io.BytesIO(json.dumps(self.__release_manifest_dict, sort_keys=True).encode("utf-8"))

    def _create(self) -> ReleaseManifest:
        """Create the manifest from GitHub asset metadata and file contents."""
        assets = {}
        for asset_name, asset_data in self.assets.items():
            entries: dict[str, AssetManifestEntry] = {}
            data = asset_data["data"]
            metadata = asset_data["metadata"]

            for file_name, file_data in data.items():
                file_metadata = file_data["metadata"]

                name = Path(file_name).name
                file_metadata.update(name=name)

                entry = AssetManifestEntry(**file_metadata)
                entries[name] = entry

            assets[asset_name] = AssetManifestMetadata(
                metadata["browser_download_url"],
                entries,
                metadata["zipped_sha256"],
                metadata["created_at"],
                metadata["label"],
            )

        release_metadata = self._parse_release_metadata()
        release_metadata.update(assets=assets)
        return ReleaseManifest(**release_metadata)

    def _parse_release_metadata(self) -> dict[str, Any]:
        """Parse relevant info from GitHub metadata for release manifest."""
        ignore = ["assets"]
        manual_set_keys = ["author", "description"]
        keys = [f.name for f in dataclasses.fields(ReleaseManifest) if f.name not in ignore + manual_set_keys]
        parsed = {k: self.release.raw_data[k] for k in keys}
        parsed.update(description=self.release.raw_data["body"], author=self.release.raw_data["author"]["login"])
        return parsed

    def save(self) -> GitReleaseAsset:
        """Save manifest files."""
        if not self.has_token:
            raise ValueError("You must provide a token to save a manifest to a GitHub release")

        asset = self.release.upload_asset_from_memory(self.release_manifest_fl, self.manifest_size, self.manifest_name)
        click.echo(f"Manifest saved as {self.manifest_name} to {self.release.html_url}")
        return asset

    @classmethod
    def load(
        cls,
        name: str,
        repo_name: str = "elastic/detection-rules",
        token: str | None = None,
    ) -> dict[str, Any] | None:
        """Load a manifest."""
        gh_client = GithubClient(token)
        repo = gh_client.client.get_repo(repo_name)
        release = get_gh_release(repo, tag_name=name)

        if not release:
            raise ValueError("No release info found")

        for asset in release.get_assets():
            if asset.name == f"manifest-{name}.json":
                return load_json_gh_asset(asset.browser_download_url)
        return None

    @classmethod
    def load_all(
        cls,
        repo_name: str = "elastic/detection-rules",
        token: str | None = None,
    ) -> tuple[dict[str, dict[str, Any]], list[str]]:
        """Load a consolidated manifest."""
        gh_client = GithubClient(token)
        repo = gh_client.client.get_repo(repo_name)

        consolidated: dict[str, dict[str, Any]] = {}
        missing: set[str] = set()
        for release in repo.get_releases():
            name = release.tag_name
            asset = next((a for a in release.get_assets() if a.name == f"manifest-{name}.json"), None)
            if not asset:
                missing.add(name)
            else:
                consolidated[name] = load_json_gh_asset(asset.browser_download_url)

        return consolidated, list(missing)

    @classmethod
    def get_existing_asset_hashes(
        cls,
        repo: str = "elastic/detection-rules",
        token: str | None = None,
    ) -> dict[str, Any]:
        """Load all assets with their hashes, by release."""
        flat: dict[str, Any] = {}
        consolidated, _ = cls.load_all(repo_name=repo, token=token)
        for release, data in consolidated.items():
            for asset in data["assets"].values():
                flat_release = flat[release] = {}
                for asset_name, asset_data in asset["entries"].items():
                    flat_release[asset_name] = asset_data["sha256"]

        return flat

    def _get_enriched_assets_from_release(self) -> dict[str, Any]:
        """Get assets and metadata from a GitHub release."""
        assets: dict[str, Any] = {}
        for asset in [a.raw_data for a in self.release.get_assets()]:
            zipped_sha256, data = load_zipped_gh_assets_with_metadata(asset["browser_download_url"])
            asset.update(zipped_sha256=zipped_sha256)

            assets[asset["name"]] = {"metadata": asset, "data": data}

        return assets
