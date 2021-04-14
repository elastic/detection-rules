# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Schemas and dataclasses for experimental ML features."""

from contextlib import contextmanager
from pathlib import Path
from typing import Dict

import click
import elasticsearch
import json
from elasticsearch import Elasticsearch
from elasticsearch.client import IngestClient, LicenseClient, MlClient

from .eswrap import es_experimental
from .ghwrap import Manifest, ReleaseManifest
from .misc import client_error
from .utils import get_path


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


@es_experimental.command('check-model-files')
@click.pass_context
def check_model_files(ctx):
    """Check ML model files on an elasticsearch instance."""
    es_client: Elasticsearch = ctx.obj['es']
    ml_client = MlClient(es_client)
    ingest_client = IngestClient(es_client)

    def safe_get(func, arg):
        try:
            return func(arg)
        except elasticsearch.NotFoundError:
            return None

    models = [m for m in ml_client.get_trained_models().get('trained_model_configs', [])
              if m['created_by'] != '_xpack']

    if models:
        if len([m for m in models if m['model_id'].startswith('dga_')]) > 1:
            click.secho('Multiple DGA models detected! It is not recommended to run more than one DGA model at a time',
                        fg='yellow')

        manifests = get_ml_model_manifests_by_model_id()

        click.echo(f'DGA Model{"s" if len(models) > 1 else ""} found:')
        for model in models:
            manifest = manifests.get(model['model_id'])
            click.echo(f'    - {model["model_id"]}, associated release: {manifest.html_url if manifest else None}')
    else:
        click.echo('No DGA Models found')

    support_files = {
        'create_script': safe_get(es_client.get_script, 'dga_ngrams_create'),
        'delete_script': safe_get(es_client.get_script, 'dga_ngrams_transform_delete'),
        'enrich_pipeline': safe_get(ingest_client.get_pipeline, 'dns_enrich_pipeline'),
        'inference_pipeline': safe_get(ingest_client.get_pipeline, 'dns_dga_inference_enrich_pipeline')
    }

    click.echo('Support Files:')
    for support_file, results in support_files.items():
        click.echo(f'    - {support_file}: {"found" if results else "not found"}')


@es_experimental.command('remove-dga-model')
@click.argument('model-id')
@click.option('--force', '-f', is_flag=True, help='Force the attempted delete without checking if model exists')
@click.pass_context
def remove_dga_model(ctx, model_id, force, es_client: Elasticsearch = None, ml_client: MlClient = None,
                     ingest_client: IngestClient = None):
    """Remove ML DGA files."""
    es_client = es_client or ctx.obj['es']
    ml_client = ml_client or MlClient(es_client)
    ingest_client = ingest_client or IngestClient(es_client)

    def safe_delete(func, fid, verbose=True):
        try:
            func(fid)
        except elasticsearch.NotFoundError:
            return False
        if verbose:
            click.echo(f' - {fid} deleted')
        return True

    model_exists = False
    if not force:
        existing_models = ml_client.get_trained_models()
        model_exists = model_id in [m['model_id'] for m in existing_models.get('trained_model_configs', [])]

    if model_exists or force:
        if model_exists:
            click.secho('[-] Existing model detected - deleting files', fg='yellow')

        deleted = [
            safe_delete(ingest_client.delete_pipeline, 'dns_dga_inference_enrich_pipeline'),
            safe_delete(ingest_client.delete_pipeline, 'dns_enrich_pipeline'),
            safe_delete(es_client.delete_script, 'dga_ngrams_transform_delete'),
            # f'{model_id}_dga_ngrams_transform_delete'
            safe_delete(es_client.delete_script, 'dga_ngrams_create'),
            # f'{model_id}_dga_ngrams_create'
            safe_delete(ml_client.delete_trained_model, model_id)
        ]

        if not any(deleted):
            click.echo('No files deleted')
    else:
        click.echo(f'Model: {model_id} not found')


expected_ml_dga_patterns = {
    'model':                                'dga_*_model.json',  # noqa: E241
    'dga_ngrams_create':                    'dga_*_ngrams_create.json',  # noqa: E241
    'dga_ngrams_transform_delete':          'dga_*_ngrams_transform_delete.json',  # noqa: E241
    'dns_enrich_pipeline':                  'dga_*_ingest_pipeline1.json',  # noqa: E241
    'dns_dga_inference_enrich_pipeline':    'dga_*_ingest_pipeline2.json'  # noqa: E241
}


@es_experimental.command('setup-dga-model')
@click.option('--model-tag', '-t',
              help='Release tag for model files staged in detection-rules (required to download files)')
@click.option('--repo', '-r', default='elastic/detection-rules',
              help='GitHub repository hosting the model file releases (owner/repo)')
@click.option('--model-dir', '-d', type=click.Path(exists=True, file_okay=False),
              help='Directory containing local model files')
@click.option('--overwrite', is_flag=True, help='Overwrite all files if already in the stack')
@click.pass_context
def setup_dga_model(ctx, model_tag, repo, model_dir, overwrite):
    """Upload ML DGA model and dependencies and enrich DNS data."""
    import io
    import requests
    import shutil
    import zipfile

    es_client: Elasticsearch = ctx.obj['es']
    client_info = es_client.info()
    license_client = LicenseClient(es_client)

    if license_client.get()['license']['type'].lower() not in ('platinum', 'enterprise'):
        client_error('You must have a platinum or enterprise subscription in order to use these ML features')

    # download files if necessary
    if not model_dir:
        if not model_tag:
            client_error('model-tag or model-dir required to download model files')

        click.echo(f'Downloading artifact: {model_tag}')

        release_url = f'https://api.github.com/repos/{repo}/releases/tags/{model_tag}'
        release = requests.get(release_url)
        release.raise_for_status()
        assets = [a for a in release.json()['assets'] if a['name'].startswith('ML-DGA') and a['name'].endswith('.zip')]

        if len(assets) != 1:
            client_error(f'Malformed release: expected 1 match ML-DGA zip, found: {len(assets)}!')

        zipped_url = assets[0]['browser_download_url']
        zipped = requests.get(zipped_url)
        z = zipfile.ZipFile(io.BytesIO(zipped.content))

        dga_dir = Path(get_path('ML-models', 'DGA'))
        model_dir = dga_dir / model_tag
        dga_dir.mkdir(parents=True, exist_ok=True)
        shutil.rmtree(str(model_dir), ignore_errors=True)
        z.extractall(str(dga_dir))
        click.echo(f'files saved to {model_dir}')

        # read files as needed
        z.close()

    def get_model_filename(pattern) -> Path:
        paths = list(Path(model_dir).glob(pattern))
        if not paths:
            client_error(f'{model_dir} missing files matching the pattern: {pattern}')
        if len(paths) > 1:
            client_error(f'{model_dir} contains multiple files matching the pattern: {pattern}')

        return paths[0]

    @contextmanager
    def open_model_file(name):
        pattern = expected_ml_dga_patterns[name]
        with open(get_model_filename(pattern), 'r') as f:
            yield json.load(f)

    model_id, _ = get_model_filename('dga_*_model.json').name.rsplit('_', maxsplit=1)

    click.echo(f'Setting up DGA model: "{model_id}" on {client_info["name"]} ({client_info["version"]["number"]})')

    # upload model
    ml_client = MlClient(es_client)
    ingest_client = IngestClient(es_client)

    existing_models = ml_client.get_trained_models()
    if model_id in [m['model_id'] for m in existing_models.get('trained_model_configs', [])]:
        if overwrite:
            ctx.invoke(remove_dga_model, model_id=model_id, es_client=es_client, ml_client=ml_client,
                       ingest_client=ingest_client, force=True)
        else:
            client_error(f'Model: {model_id} already exists on stack! Try --overwrite to force the upload')

    click.secho('[+] Uploading model (may take a while)')

    with open_model_file('model') as model_file:
        try:
            ml_client.put_trained_model(model_id=model_id, body=model_file)
        except elasticsearch.ConnectionTimeout:
            msg = 'Connection timeout, try increasing timeout using `es --timeout <secs> experimental setup_dga_model`.'
            client_error(msg)

    # install scripts
    click.secho('[+] Uploading painless scripts')

    with open_model_file('dga_ngrams_create') as painless_install:
        es_client.put_script(id='dga_ngrams_create', body=painless_install)
        # f'{model_id}_dga_ngrams_create'

    with open_model_file('dga_ngrams_transform_delete') as painless_delete:
        es_client.put_script(id='dga_ngrams_transform_delete', body=painless_delete)
        # f'{model_id}_dga_ngrams_transform_delete'

    # Install ingest pipelines
    click.secho('[+] Uploading pipelines')

    def _build_es_script_error(err, pipeline_file):
        error = err.info['error']
        cause = error['caused_by']

        error_msg = [
            f'Script error while uploading {pipeline_file}: {cause["type"]} - {cause["reason"]}',
            ' '.join(f'{k}: {v}' for k, v in error['position'].items()),
            '\n'.join(error['script_stack'])
        ]

        return click.style('\n'.join(error_msg), fg='red')

    with open_model_file('dns_enrich_pipeline') as ingest_pipeline1:
        try:
            ingest_client.put_pipeline(id='dns_enrich_pipeline', body=ingest_pipeline1)
        except elasticsearch.RequestError as e:
            if e.error == 'script_exception':
                client_error(_build_es_script_error(e, 'ingest_pipeline1'), e, ctx=ctx)
            else:
                raise

    with open_model_file('dns_dga_inference_enrich_pipeline') as ingest_pipeline2:
        try:
            ingest_client.put_pipeline(id='dns_dga_inference_enrich_pipeline', body=ingest_pipeline2)
        except elasticsearch.RequestError as e:
            if e.error == 'script_exception':
                client_error(_build_es_script_error(e, 'ingest_pipeline2'), e, ctx=ctx)
            else:
                raise

    click.echo('Ensure that you have updated your packetbeat.yml config file.')
    click.echo('    - reference: ML_DGA.md #2-update-packetbeat-configuration')
    click.echo('Associated rules and jobs can be found under ML-experimental-detections releases in the repo')
    click.echo('To upload rules, run: kibana upload-rule <ml-rule.toml>')
    click.echo('To upload ML jobs, run: es experimental upload-ml-job <ml-job.json>')


@es_experimental.command('upload-ml-job')
@click.argument('job-file', type=click.Path(exists=True, dir_okay=False))
@click.option('--overwrite', '-o', is_flag=True, help='Overwrite job if exists by name')
@click.pass_context
def upload_ml_job(ctx: click.Context, job_file, overwrite):
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
                ctx.invoke(delete_ml_job, job_name=name, job_type=job_type)
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


@es_experimental.command('delete-ml-job')
@click.argument('job-name')
@click.argument('job-type')
@click.pass_context
def delete_ml_job(ctx: click.Context, job_name, job_type, verbose=True):
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
