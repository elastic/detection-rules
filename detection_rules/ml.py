# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Schemas and dataclasses for experimental ML features."""

import io
import json
import zipfile
from dataclasses import dataclass
from functools import cached_property, lru_cache
from pathlib import Path
from typing import Any, Literal

import click
import elasticsearch
import requests
from elasticsearch import Elasticsearch
from elasticsearch.client import IngestClient, LicenseClient, MlClient

from .ghwrap import ManifestManager, ReleaseManifest
from .schemas import definitions
from .utils import get_path, unzip_to_dict

ML_PATH = get_path(["machine-learning"])


def info_from_tag(tag: str) -> tuple[Literal["ml"], str, str, int]:
    try:
        ml, release_type, release_date, release_number = tag.split("-")
    except ValueError as exc:
        raise ValueError(f"{tag} is not of valid release format: ml-type-date-number. {exc}") from exc

    if ml != "ml":
        raise ValueError(f"Invalid type from the tag: {ml}")

    if release_type not in definitions.MACHINE_LEARNING_PACKAGES:
        raise ValueError(f"Unexpected release type encountered: {release_type}")

    return ml, release_type, release_date, int(release_number)


class InvalidLicenseError(Exception):
    """Invalid stack license for ML features requiring platinum or enterprise."""


@dataclass
class MachineLearningClient:
    """Class for experimental machine learning release clients."""

    es_client: Elasticsearch
    bundle: dict[str, Any]

    @cached_property
    def model_id(self) -> str:
        return next(data["model_id"] for name, data in self.bundle.items() if Path(name).stem.lower().endswith("model"))

    @cached_property
    def bundle_type(self) -> str:
        return self.model_id.split("_")[0].lower()

    @cached_property
    def ml_client(self) -> MlClient:
        return MlClient(self.es_client)

    @cached_property
    def ingest_client(self) -> IngestClient:
        return IngestClient(self.es_client)

    @cached_property
    def license(self) -> str:
        license_client = LicenseClient(self.es_client)
        return license_client.get()["license"]["type"].lower()

    @staticmethod
    @lru_cache
    def ml_manifests() -> dict[str, ReleaseManifest]:
        return get_ml_model_manifests_by_model_id()

    def verify_license(self) -> None:
        valid_license = self.license in ("platinum", "enterprise")

        if not valid_license:
            raise InvalidLicenseError(
                "Your subscription level does not support Machine Learning. See "
                "https://www.elastic.co/subscriptions for more information."
            )

    @classmethod
    def from_release(
        cls, es_client: Elasticsearch, release_tag: str, repo: str = "elastic/detection-rules"
    ) -> "MachineLearningClient":
        """Load from a GitHub release."""

        ml, release_type, _, _ = info_from_tag(release_tag)

        full_type = f"{ml}-{release_type}"
        release_url = f"https://api.github.com/repos/{repo}/releases/tags/{release_tag}"
        release = requests.get(release_url, timeout=30)
        release.raise_for_status()

        # check that the release only has a single zip file
        assets = [a for a in release.json()["assets"] if a["name"].startswith(full_type) and a["name"].endswith(".zip")]
        if len(assets) != 1:
            raise ValueError(f"Malformed release: expected 1 {full_type} zip file, found: {len(assets)}!")

        zipped_url = assets[0]["browser_download_url"]
        zipped_raw = requests.get(zipped_url, timeout=30)
        zipped_bundle = zipfile.ZipFile(io.BytesIO(zipped_raw.content))
        bundle = unzip_to_dict(zipped_bundle)

        return cls(es_client=es_client, bundle=bundle)

    @classmethod
    def from_directory(cls, es_client: Elasticsearch, directory: Path) -> "MachineLearningClient":
        """Load from an unzipped local directory."""
        bundle = json.loads(directory.read_text())
        return cls(es_client=es_client, bundle=bundle)

    def remove(self) -> dict[str, dict[str, Any]]:
        """Remove machine learning files from a stack."""
        results = {"script": {}, "pipeline": {}, "model": {}}  # type: ignore[reportUnknownVariableType]
        for pipeline in list(self.get_related_pipelines()):
            results["pipeline"][pipeline] = self.ingest_client.delete_pipeline(id=pipeline)
        for script in list(self.get_related_scripts()):
            results["script"][script] = self.es_client.delete_script(id=script)

        results["model"][self.model_id] = self.ml_client.delete_trained_model(model_id=self.model_id)
        return results  # type: ignore[reportUnknownVariableType]

    def setup(self) -> dict[str, Any]:
        """Setup machine learning bundle on a stack."""
        self.verify_license()
        results = {"script": {}, "pipeline": {}, "model": {}}  # type: ignore[reportUnknownVariableType]

        # upload in order: model, scripts, then pipelines
        parsed_bundle = {"model": {}, "script": {}, "pipeline": {}}  # type: ignore[reportUnknownVariableType]
        for filename, data in self.bundle.items():
            fp = Path(filename)
            file_type = fp.stem.split("_")[-1]
            parsed_bundle[file_type][fp.stem] = data

        model = next(parsed_bundle["model"].values())  # type: ignore[reportArgumentType]
        results["model"][model["model_id"]] = self.upload_model(model["model_id"], model)  # type: ignore[reportUnknownArgumentType]

        for script_name, script in parsed_bundle["script"].items():  # type: ignore[reportArgumentType]
            results["script"][script_name] = self.upload_script(script_name, script)  # type: ignore[reportUnknownArgumentType]

        for pipeline_name, pipeline in parsed_bundle["pipeline"].items():  # type: ignore[reportArgumentType]
            results["pipeline"][pipeline_name] = self.upload_ingest_pipeline(pipeline_name, pipeline)  # type: ignore[reportUnknownArgumentType]

        return results  # type: ignore[reportUnknownVariableType]

    def get_all_scripts(self) -> dict[str, dict[str, Any]]:
        """Get all scripts from an elasticsearch instance."""
        return self.es_client.cluster.state()["metadata"]["stored_scripts"]

    def get_related_scripts(self) -> dict[str, dict[str, Any]]:
        """Get all scripts which start with ml_*."""
        scripts = self.get_all_scripts()
        return {n: s for n, s in scripts.items() if n.lower().startswith(f"ml_{self.bundle_type}")}

    def get_related_pipelines(self) -> dict[str, dict[str, Any]]:
        """Get all pipelines which start with ml_*."""
        pipelines = self.ingest_client.get_pipeline()
        return {n: s for n, s in pipelines.items() if n.lower().startswith(f"ml_{self.bundle_type}")}

    def get_related_model(self) -> dict[str, Any] | None:
        """Get a model from an elasticsearch instance matching the model_id."""
        for model in self.get_all_existing_model_files():
            if model["model_id"] == self.model_id:
                return model
        return None

    def get_all_existing_model_files(self) -> list[dict[str, Any]]:
        """Get available models from a stack."""
        return self.ml_client.get_trained_models()["trained_model_configs"]

    @classmethod
    def get_existing_model_ids(cls, es_client: Elasticsearch) -> list[str]:
        """Get model IDs for existing ML models."""
        ml_client = MlClient(es_client)
        return [
            m["model_id"]
            for m in ml_client.get_trained_models()["trained_model_configs"]
            if m["model_id"] in cls.ml_manifests()
        ]

    @classmethod
    def check_model_exists(cls, es_client: Elasticsearch, model_id: str) -> bool:
        """Check if a model exists on a stack by model id."""
        ml_client = MlClient(es_client)
        return model_id in [m["model_id"] for m in ml_client.get_trained_models()["trained_model_configs"]]

    def get_related_files(self) -> dict[str, Any]:
        """Check for the presence and status of ML bundle files on a stack."""
        return {
            "pipeline": self.get_related_pipelines(),
            "script": self.get_related_scripts(),
            "model": self.get_related_model(),
            "release": self.get_related_release(),
        }

    def get_related_release(self) -> ReleaseManifest:
        """Get the GitHub release related to a model."""
        return self.ml_manifests.get(self.model_id)  # type: ignore[reportAttributeAccessIssue]

    @classmethod
    def get_all_ml_files(cls, es_client: Elasticsearch) -> dict[str, Any]:
        """Get all scripts, pipelines, and models which start with ml_*."""
        pipelines = IngestClient(es_client).get_pipeline()
        scripts = es_client.cluster.state()["metadata"]["stored_scripts"]
        models = MlClient(es_client).get_trained_models()["trained_model_configs"]
        manifests = get_ml_model_manifests_by_model_id()

        return {
            "pipeline": {n: s for n, s in pipelines.items() if n.lower().startswith("ml_")},
            "script": {n: s for n, s in scripts.items() if n.lower().startswith("ml_")},
            "model": {
                m["model_id"]: {"model": m, "release": manifests[m["model_id"]]}
                for m in models
                if m["model_id"] in manifests
            },
        }

    @classmethod
    def remove_ml_scripts_pipelines(cls, es_client: Elasticsearch, ml_type: list[str]) -> dict[str, Any]:
        """Remove all ML script and pipeline files."""
        results = {"script": {}, "pipeline": {}}  # type: ignore[reportUnknownVariableType]
        ingest_client = IngestClient(es_client)

        files = cls.get_all_ml_files(es_client=es_client)
        for file_type, data in files.items():
            for name in list(data):
                this_type = name.split("_")[1].lower()
                if this_type not in ml_type:
                    continue
                if file_type == "script":
                    results[file_type][name] = es_client.delete_script(id=name)
                elif file_type == "pipeline":
                    results[file_type][name] = ingest_client.delete_pipeline(id=name)

        return results  # type: ignore[reportUnknownVariableType]

    def upload_model(self, model_id: str, body: dict[str, Any]) -> Any:
        """Upload an ML model file."""
        return self.ml_client.put_trained_model(model_id=model_id, body=body)

    def upload_script(self, script_id: str, body: dict[str, Any]) -> Any:
        """Install a script file."""
        return self.es_client.put_script(id=script_id, body=body)

    def upload_ingest_pipeline(self, pipeline_id: str, body: dict[str, Any]) -> Any:
        """Install a pipeline file."""
        return self.ingest_client.put_pipeline(id=pipeline_id, body=body)

    @staticmethod
    def _build_script_error(exc: elasticsearch.RequestError, pipeline_file: str) -> str:
        """Build an error for a failed script upload."""
        error = exc.info["error"]
        cause = error["caused_by"]
        error_msg = [
            f"Script error while uploading {pipeline_file}: {cause['type']} - {cause['reason']}",
            " ".join(f"{k}: {v}" for k, v in error["position"].items()),
            "\n".join(error["script_stack"]),
        ]

        return click.style("\n".join(error_msg), fg="red")


def get_ml_model_manifests_by_model_id(repo_name: str = "elastic/detection-rules") -> dict[str, ReleaseManifest]:
    """Load all ML DGA model release manifests by model id."""
    manifests, _ = ManifestManager.load_all(repo_name=repo_name)
    model_manifests: dict[str, ReleaseManifest] = {}

    for manifest in manifests.values():
        for asset in manifest["assets"].values():
            for entry_name in asset["entries"]:
                if entry_name.startswith("dga") and entry_name.endswith("model.json"):
                    model_id, _ = entry_name.rsplit("_", 1)
                    model_manifests[model_id] = ReleaseManifest(**manifest)
                    break

    return model_manifests
