# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Schemas and dataclasses for experimental ML features."""

import io
import zipfile
from dataclasses import dataclass
from functools import cached_property, lru_cache
from pathlib import Path
from typing import Dict, List, Literal, Optional

import click
import elasticsearch
import json
import requests
from eql.table import Table
from elasticsearch import Elasticsearch
from elasticsearch.client import IngestClient, LicenseClient, MlClient

from .eswrap import es_experimental
from .ghwrap import ManifestManager, ReleaseManifest
from .misc import client_error
from .schemas import definitions
from .utils import get_path, unzip_to_dict


ML_PATH = Path(get_path('machine-learning'))


def info_from_tag(tag: str) -> (Literal['ml'], definitions.MachineLearningType, str, int):
    try:
        ml, release_type, release_date, release_number = tag.split('-')
    except ValueError as exc:
        raise ValueError(f'{tag} is not of valid release format: ml-type-date-number. {exc}')

    return ml, release_type, release_date, int(release_number)


class InvalidLicenseError(Exception):
    """Invalid stack license for ML features requiring platinum or enterprise."""


@dataclass
class MachineLearningClient:
    """Class for experimental machine learning release clients."""

    es_client: Elasticsearch
    bundle: dict

    @cached_property
    def model_id(self) -> str:
        return next(data['model_id'] for name, data in self.bundle.items() if Path(name).stem.lower().endswith('model'))

    @cached_property
    def bundle_type(self) -> str:
        return self.model_id.split('_')[0].lower()

    @cached_property
    def ml_client(self) -> MlClient:
        return MlClient(self.es_client)

    @cached_property
    def ingest_client(self) -> IngestClient:
        return IngestClient(self.es_client)

    @cached_property
    def license(self) -> str:
        license_client = LicenseClient(self.es_client)
        return license_client.get()['license']['type'].lower()

    @staticmethod
    @lru_cache
    def ml_manifests() -> Dict[str, ReleaseManifest]:
        return get_ml_model_manifests_by_model_id()

    def verify_license(self):
        valid_license = self.license in ('platinum', 'enterprise')

        if not valid_license:
            err_msg = 'Your subscription level does not support Machine Learning. See ' \
                      'https://www.elastic.co/subscriptions for more information.'
            raise InvalidLicenseError(err_msg)

    @classmethod
    def from_release(cls, es_client: Elasticsearch, release_tag: str,
                     repo: str = 'elastic/detection-rules') -> 'MachineLearningClient':
        """Load from a GitHub release."""
        full_type = '-'.join(info_from_tag(release_tag)[:2])
        release_url = f'https://api.github.com/repos/{repo}/releases/tags/{release_tag}'
        release = requests.get(release_url)
        release.raise_for_status()

        # check that the release only has a single zip file
        assets = [a for a in release.json()['assets'] if
                  a['name'].startswith(full_type) and a['name'].endswith('.zip')]
        assert len(assets) == 1, f'Malformed release: expected 1 {full_type} zip file, found: {len(assets)}!'

        zipped_url = assets[0]['browser_download_url']
        zipped_raw = requests.get(zipped_url)
        zipped_bundle = zipfile.ZipFile(io.BytesIO(zipped_raw.content))
        bundle = unzip_to_dict(zipped_bundle)

        return cls(es_client=es_client, bundle=bundle)

    @classmethod
    def from_directory(cls, es_client: Elasticsearch, directory: Path) -> 'MachineLearningClient':
        """Load from an unzipped local directory."""
        bundle = json.loads(directory.read_text())
        return cls(es_client=es_client, bundle=bundle)

    def remove(self) -> dict:
        """Remove machine learning files from a stack."""
        results = dict(script={}, pipeline={}, model={})
        for pipeline in list(self.get_related_pipelines()):
            results['pipeline'][pipeline] = self.ingest_client.delete_pipeline(pipeline)
        for script in list(self.get_related_scripts()):
            results['script'][script] = self.es_client.delete_script(script)

        results['model'][self.model_id] = self.ml_client.delete_trained_model(self.model_id)
        return results

    def setup(self) -> dict:
        """Setup machine learning bundle on a stack."""
        self.verify_license()
        results = dict(script={}, pipeline={}, model={})

        # upload in order: model, scripts, then pipelines
        parsed_bundle = dict(model={}, script={}, pipeline={})
        for filename, data in self.bundle.items():
            fp = Path(filename)
            file_type = fp.stem.split('_')[-1]
            parsed_bundle[file_type][fp.stem] = data

        model = list(parsed_bundle['model'].values())[0]
        results['model'][model['model_id']] = self.upload_model(model['model_id'], model)

        for script_name, script in parsed_bundle['script'].items():
            results['script'][script_name] = self.upload_script(script_name, script)

        for pipeline_name, pipeline in parsed_bundle['pipeline'].items():
            results['pipeline'][pipeline_name] = self.upload_ingest_pipeline(pipeline_name, pipeline)

        return results

    def get_all_scripts(self) -> Dict[str, dict]:
        """Get all scripts from an elasticsearch instance."""
        return self.es_client.cluster.state()['metadata']['stored_scripts']

    def get_related_scripts(self) -> Dict[str, dict]:
        """Get all scripts which start with ml_*."""
        scripts = self.get_all_scripts()
        return {n: s for n, s in scripts.items() if n.lower().startswith(f'ml_{self.bundle_type}')}

    def get_related_pipelines(self) -> Dict[str, dict]:
        """Get all pipelines which start with ml_*."""
        pipelines = self.ingest_client.get_pipeline()
        return {n: s for n, s in pipelines.items() if n.lower().startswith(f'ml_{self.bundle_type}')}

    def get_related_model(self) -> Optional[dict]:
        """Get a model from an elasticsearch instance matching the model_id."""
        for model in self.get_all_existing_model_files():
            if model['model_id'] == self.model_id:
                return model

    def get_all_existing_model_files(self) -> dict:
        """Get available models from a stack."""
        return self.ml_client.get_trained_models()['trained_model_configs']

    @classmethod
    def get_existing_model_ids(cls, es_client: Elasticsearch) -> List[str]:
        """Get model IDs for existing ML models."""
        ml_client = MlClient(es_client)
        return [m['model_id'] for m in ml_client.get_trained_models()['trained_model_configs']
                if m['model_id'] in cls.ml_manifests()]

    @classmethod
    def check_model_exists(cls, es_client: Elasticsearch, model_id: str) -> bool:
        """Check if a model exists on a stack by model id."""
        ml_client = MlClient(es_client)
        return model_id in [m['model_id'] for m in ml_client.get_trained_models()['trained_model_configs']]

    def get_related_files(self) -> dict:
        """Check for the presence and status of ML bundle files on a stack."""
        files = {
            'pipeline': self.get_related_pipelines(),
            'script': self.get_related_scripts(),
            'model': self.get_related_model(),
            'release': self.get_related_release()
        }
        return files

    def get_related_release(self) -> ReleaseManifest:
        """Get the GitHub release related to a model."""
        return self.ml_manifests.get(self.model_id)

    @classmethod
    def get_all_ml_files(cls, es_client: Elasticsearch) -> dict:
        """Get all scripts, pipelines, and models which start with ml_*."""
        pipelines = IngestClient(es_client).get_pipeline()
        scripts = es_client.cluster.state()['metadata']['stored_scripts']
        models = MlClient(es_client).get_trained_models()['trained_model_configs']
        manifests = get_ml_model_manifests_by_model_id()

        files = {
            'pipeline': {n: s for n, s in pipelines.items() if n.lower().startswith('ml_')},
            'script': {n: s for n, s in scripts.items() if n.lower().startswith('ml_')},
            'model': {m['model_id']: {'model': m, 'release': manifests[m['model_id']]}
                      for m in models if m['model_id'] in manifests},
        }
        return files

    @classmethod
    def remove_ml_scripts_pipelines(cls, es_client: Elasticsearch, ml_type: List[str]) -> dict:
        """Remove all ML script and pipeline files."""
        results = dict(script={}, pipeline={})
        ingest_client = IngestClient(es_client)

        files = cls.get_all_ml_files(es_client=es_client)
        for file_type, data in files.items():
            for name in list(data):
                this_type = name.split('_')[1].lower()
                if this_type not in ml_type:
                    continue
                if file_type == 'script':
                    results[file_type][name] = es_client.delete_script(name)
                elif file_type == 'pipeline':
                    results[file_type][name] = ingest_client.delete_pipeline(name)

        return results

    def upload_model(self, model_id: str, body: dict) -> dict:
        """Upload an ML model file."""
        return self.ml_client.put_trained_model(model_id=model_id, body=body)

    def upload_script(self, script_id: str, body: dict) -> dict:
        """Install a script file."""
        return self.es_client.put_script(id=script_id, body=body)

    def upload_ingest_pipeline(self, pipeline_id: str, body: dict) -> dict:
        """Install a pipeline file."""
        return self.ingest_client.put_pipeline(id=pipeline_id, body=body)

    @staticmethod
    def _build_script_error(exc: elasticsearch.RequestError, pipeline_file: str):
        """Build an error for a failed script upload."""
        error = exc.info['error']
        cause = error['caused_by']
        error_msg = [
            f'Script error while uploading {pipeline_file}: {cause["type"]} - {cause["reason"]}',
            ' '.join(f'{k}: {v}' for k, v in error['position'].items()),
            '\n'.join(error['script_stack'])
        ]

        return click.style('\n'.join(error_msg), fg='red')


def get_ml_model_manifests_by_model_id(repo: str = 'elastic/detection-rules') -> Dict[str, ReleaseManifest]:
    """Load all ML DGA model release manifests by model id."""
    manifests, _ = ManifestManager.load_all(repo=repo)
    model_manifests = {}

    for manifest_name, manifest in manifests.items():
        for asset_name, asset in manifest['assets'].items():
            for entry_name, entry_data in asset['entries'].items():
                if entry_name.startswith('dga') and entry_name.endswith('model.json'):
                    model_id, _ = entry_name.rsplit('_', 1)
                    model_manifests[model_id] = ReleaseManifest(**manifest)
                    break

    return model_manifests


@es_experimental.group('ml')
def ml_group():
    """Experimental machine learning commands."""


@ml_group.command('check-files')
@click.pass_context
def check_files(ctx):
    """Check ML model files on an elasticsearch instance."""
    files = MachineLearningClient.get_all_ml_files(ctx.obj['es'])

    results = []
    for file_type, data in files.items():
        if file_type == 'model':
            continue
        for name in list(data):
            results.append({'file_type': file_type, 'name': name})

    for model_name, model in files['model'].items():
        results.append({'file_type': 'model', 'name': model_name, 'related_release': model['release'].tag_name})

    fields = ['file_type', 'name', 'related_release']
    table = Table.from_list(fields, results)
    click.echo(table)
    return files


@ml_group.command('remove-model')
@click.argument('model-id', required=False)
@click.pass_context
def remove_model(ctx: click.Context, model_id):
    """Remove ML model files."""
    es_client = MlClient(ctx.obj['es'])
    model_ids = MachineLearningClient.get_existing_model_ids(ctx.obj['es'])

    if not model_id:
        model_id = click.prompt('Model ID to remove', type=click.Choice(model_ids))

    try:
        result = es_client.delete_trained_model(model_id)
    except elasticsearch.ConflictError as e:
        click.echo(f'{e}: try running `remove-scripts-pipelines` first')
        ctx.exit(1)

    table = Table.from_list(['model_id', 'status'], [{'model_id': model_id, 'status': result}])
    click.echo(table)
    return result


@ml_group.command('remove-scripts-pipelines')
@click.option('--dga', is_flag=True)
@click.option('--problemchild', is_flag=True)
@click.pass_context
def remove_scripts_pipelines(ctx: click.Context, **ml_types):
    """Remove ML scripts and pipeline files."""
    selected_types = [k for k, v in ml_types.items() if v]
    assert selected_types, f'Specify ML types to remove: {list(ml_types)}'
    status = MachineLearningClient.remove_ml_scripts_pipelines(es_client=ctx.obj['es'], ml_type=selected_types)

    results = []
    for file_type, response in status.items():
        for name, result in response.items():
            results.append({'file_type': file_type, 'name': name, 'status': result})

    fields = ['file_type', 'name', 'status']
    table = Table.from_list(fields, results)
    click.echo(table)
    return status


@ml_group.command('setup')
@click.option('--model-tag', '-t',
              help='Release tag for model files staged in detection-rules (required to download files)')
@click.option('--repo', '-r', default='elastic/detection-rules',
              help='GitHub repository hosting the model file releases (owner/repo)')
@click.option('--model-dir', '-d', type=click.Path(exists=True, file_okay=False),
              help='Directory containing local model files')
@click.pass_context
def setup_bundle(ctx, model_tag, repo, model_dir):
    """Upload ML model and dependencies to enrich data."""
    es_client: Elasticsearch = ctx.obj['es']

    if model_tag:
        dga_client = MachineLearningClient.from_release(es_client=es_client, release_tag=model_tag, repo=repo)
    elif model_dir:
        dga_client = MachineLearningClient.from_directory(es_client=es_client, directory=model_dir)
    else:
        return client_error('model-tag or model-dir required to download model files')

    dga_client.verify_license()
    status = dga_client.setup()

    results = []
    for file_type, response in status.items():
        for name, result in response.items():
            if file_type == 'model':
                status = 'success' if result.get('create_time') else 'potential_failure'
                results.append({'file_type': file_type, 'name': name, 'status': status})
                continue
            results.append({'file_type': file_type, 'name': name, 'status': result})

    fields = ['file_type', 'name', 'status']
    table = Table.from_list(fields, results)
    click.echo(table)

    click.echo('Associated rules and jobs can be found under ML-experimental-detections releases in the repo')
    click.echo('To upload rules, run: kibana upload-rule <ml-rule.toml>')
    click.echo('To upload ML jobs, run: es experimental upload-ml-job <ml-job.json>')


@ml_group.command('upload-job')
@click.argument('job-file', type=click.Path(exists=True, dir_okay=False))
@click.option('--overwrite', '-o', is_flag=True, help='Overwrite job if exists by name')
@click.pass_context
def upload_job(ctx: click.Context, job_file, overwrite):
    """Upload experimental ML jobs."""
    es_client: Elasticsearch = ctx.obj['es']
    ml_client = MlClient(es_client)

    with open(job_file, 'r') as f:
        job = json.load(f)

    def safe_upload(func):
        try:
            func(name, body)
        except (elasticsearch.ConflictError, elasticsearch.RequestError) as err:
            if isinstance(err, elasticsearch.RequestError) and err.error != 'resource_already_exists_exception':
                client_error(str(err), err, ctx=ctx)

            if overwrite:
                ctx.invoke(delete_job, job_name=name, job_type=job_type)
                func(name, body)
            else:
                client_error(str(err), err, ctx=ctx)

    try:
        job_type = job['type']
        name = job['name']
        body = job['body']

        if job_type == 'anomaly_detection':
            safe_upload(ml_client.put_job)
        elif job_type == 'data_frame_analytic':
            safe_upload(ml_client.put_data_frame_analytics)
        elif job_type == 'datafeed':
            safe_upload(ml_client.put_datafeed)
        else:
            client_error(f'Unknown ML job type: {job_type}')

        click.echo(f'Uploaded {job_type} job: {name}')
    except KeyError as e:
        client_error(f'{job_file} missing required info: {e}')


@ml_group.command('delete-job')
@click.argument('job-name')
@click.argument('job-type')
@click.pass_context
def delete_job(ctx: click.Context, job_name, job_type, verbose=True):
    """Remove experimental ML jobs."""
    es_client: Elasticsearch = ctx.obj['es']
    ml_client = MlClient(es_client)

    try:
        if job_type == 'anomaly_detection':
            ml_client.delete_job(job_name)
        elif job_type == 'data_frame_analytic':
            ml_client.delete_data_frame_analytics(job_name)
        elif job_type == 'datafeed':
            ml_client.delete_datafeed(job_name)
        else:
            client_error(f'Unknown ML job type: {job_type}')
    except (elasticsearch.NotFoundError, elasticsearch.ConflictError) as e:
        client_error(str(e), e, ctx=ctx)

    if verbose:
        click.echo(f'Deleted {job_type} job: {job_name}')
