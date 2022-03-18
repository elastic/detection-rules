# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Misc support."""
import os
import re
import time
import uuid
from pathlib import Path

from functools import wraps
from typing import NoReturn

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

from .utils import add_params, cached, get_path

_CONFIG = {}

LICENSE_HEADER = """
Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
or more contributor license agreements. Licensed under the Elastic License
2.0; you may not use this file except in compliance with the Elastic License
2.0.
""".strip()

LICENSE_LINES = LICENSE_HEADER.splitlines()
PYTHON_LICENSE = "\n".join("# " + line for line in LICENSE_LINES)
JS_LICENSE = """
/*
{}
 */
""".strip().format("\n".join(' * ' + line for line in LICENSE_LINES))


class ClientError(click.ClickException):
    """Custom CLI error to format output or full debug stacktrace."""

    def __init__(self, message, original_error=None):
        super(ClientError, self).__init__(message)
        self.original_error = original_error
        self.original_error_type = type(original_error).__name__ if original_error else ''

    def show(self, file=None, err=True):
        """Print the error to the console."""
        # err_msg = f' {self.original_error_type}' if self.original_error else ''
        msg = f'{click.style(f"CLI Error ({self.original_error_type})", fg="red", bold=True)}: {self.format_message()}'
        click.echo(msg, err=err, file=file)


def client_error(message, exc: Exception = None, debug=None, ctx: click.Context = None, file=None,
                 err=None) -> NoReturn:
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
            if required and value is None:
                continue
            else:
                return [_convert_type(r) for r in result_list]
        else:
            if _check_type(result):
                return _convert_type(result)
            elif required:
                value = None
                continue
            return


def get_kibana_rules_map(repo='elastic/kibana', branch='master'):
    """Get list of available rules from the Kibana repo and return a list of URLs."""
    # ensure branch exists
    r = requests.get(f'https://api.github.com/repos/{repo}/branches/{branch}')
    r.raise_for_status()

    url = ('https://api.github.com/repos/{repo}/contents/x-pack/{legacy}plugins/{app}/server/lib/'
           'detection_engine/rules/prepackaged_rules?ref={branch}')

    gh_rules = requests.get(url.format(legacy='', app='security_solution', branch=branch, repo=repo)).json()

    # pre-7.9 app was siem
    if isinstance(gh_rules, dict) and gh_rules.get('message', '') == 'Not Found':
        gh_rules = requests.get(url.format(legacy='', app='siem', branch=branch, repo=repo)).json()

    # pre-7.8 the siem was under the legacy directory
    if isinstance(gh_rules, dict) and gh_rules.get('message', '') == 'Not Found':
        gh_rules = requests.get(url.format(legacy='legacy/', app='siem', branch=branch, repo=repo)).json()

    if isinstance(gh_rules, dict) and gh_rules.get('message', '') == 'Not Found':
        raise ValueError(f'rules directory does not exist for {repo} branch: {branch}')

    return {os.path.splitext(r['name'])[0]: r['download_url'] for r in gh_rules if r['name'].endswith('.json')}


def get_kibana_rules(*rule_paths, repo='elastic/kibana', branch='master', verbose=True, threads=50):
    """Retrieve prepackaged rules from kibana repo."""
    from multiprocessing.pool import ThreadPool

    kibana_rules = {}

    if verbose:
        thread_use = f' using {threads} threads' if threads > 1 else ''
        click.echo(f'Downloading rules from {repo} {branch} branch in kibana repo{thread_use} ...')

    rule_paths = [os.path.splitext(os.path.basename(p))[0] for p in rule_paths]
    rules_mapping = [(n, u) for n, u in get_kibana_rules_map(repo=repo, branch=branch).items() if n in rule_paths] \
        if rule_paths else get_kibana_rules_map(repo=repo, branch=branch).items()

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
    import eql

    config_file = next(Path(get_path()).glob('.detection-rules-cfg.*'), None)
    config = {}

    if config_file and config_file.exists():
        config = eql.utils.load_dump(str(config_file))

        click.secho(f'Loaded config file: {config_file}', fg='yellow')

    return config


def getdefault(name):
    """Callback function for `default` to get an environment variable."""
    envvar = f"DR_{name.upper()}"
    config = parse_config()
    return lambda: os.environ.get(envvar, config.get(name))


def get_elasticsearch_client(cloud_id=None, elasticsearch_url=None, es_user=None, es_password=None, ctx=None, **kwargs):
    """Get an authenticated elasticsearch client."""
    from elasticsearch import AuthenticationException, Elasticsearch

    if not (cloud_id or elasticsearch_url):
        client_error("Missing required --cloud-id or --elasticsearch-url")

    # don't prompt for these until there's a cloud id or elasticsearch URL
    es_user = es_user or click.prompt("es_user")
    es_password = es_password or click.prompt("es_password", hide_input=True)
    hosts = [elasticsearch_url] if elasticsearch_url else None
    timeout = kwargs.pop('timeout', 60)
    kwargs['verify_certs'] = not kwargs.pop('ignore_ssl_errors', False)

    try:
        client = Elasticsearch(hosts=hosts, cloud_id=cloud_id, http_auth=(es_user, es_password), timeout=timeout,
                               **kwargs)
        # force login to test auth
        client.info()
        return client
    except AuthenticationException as e:
        error_msg = f'Failed authentication for {elasticsearch_url or cloud_id}'
        client_error(error_msg, e, ctx=ctx, err=True)


def get_kibana_client(cloud_id, kibana_url, kibana_user, kibana_password, kibana_cookie, space, ignore_ssl_errors,
                      provider_type, provider_name, **kwargs):
    """Get an authenticated Kibana client."""
    from requests import HTTPError
    from kibana import Kibana

    if not (cloud_id or kibana_url):
        client_error("Missing required --cloud-id or --kibana-url")

    if not kibana_cookie:
        # don't prompt for these until there's a cloud id or Kibana URL
        kibana_user = kibana_user or click.prompt("kibana_user")
        kibana_password = kibana_password or click.prompt("kibana_password", hide_input=True)

    verify = not ignore_ssl_errors

    with Kibana(cloud_id=cloud_id, kibana_url=kibana_url, space=space, verify=verify, **kwargs) as kibana:
        if kibana_cookie:
            kibana.add_cookie(kibana_cookie)
            return kibana

        try:
            kibana.login(kibana_user, kibana_password, provider_type=provider_type, provider_name=provider_name)
        except HTTPError as exc:
            if exc.response.status_code == 401:
                err_msg = f'Authentication failed for {kibana_url}. If credentials are valid, check --provider-name'
                client_error(err_msg, exc, err=True)
            else:
                raise

        return kibana


client_options = {
    'kibana': {
        'cloud_id': click.Option(['--cloud-id'], default=getdefault('cloud_id')),
        'kibana_cookie': click.Option(['--kibana-cookie', '-kc'], default=getdefault('kibana_cookie'),
                                      help='Cookie from an authed session'),
        'kibana_password': click.Option(['--kibana-password', '-kp'], default=getdefault('kibana_password')),
        'kibana_url': click.Option(['--kibana-url'], default=getdefault('kibana_url')),
        'kibana_user': click.Option(['--kibana-user', '-ku'], default=getdefault('kibana_user')),
        'provider_type': click.Option(['--provider-type'], default=getdefault('provider_type')),
        'provider_name': click.Option(['--provider-name'], default=getdefault('provider_name')),
        'space': click.Option(['--space'], default=None, help='Kibana space'),
        'ignore_ssl_errors': click.Option(['--ignore-ssl-errors'], default=getdefault('ignore_ssl_errors'))
    },
    'elasticsearch': {
        'cloud_id': click.Option(['--cloud-id'], default=getdefault("cloud_id")),
        'elasticsearch_url': click.Option(['--elasticsearch-url'], default=getdefault("elasticsearch_url")),
        'es_user': click.Option(['--es-user', '-eu'], default=getdefault("es_user")),
        'es_password': click.Option(['--es-password', '-ep'], default=getdefault("es_password")),
        'timeout': click.Option(['--timeout', '-et'], default=60, help='Timeout for elasticsearch client'),
        'ignore_ssl_errors': click.Option(['--ignore-ssl-errors'], default=getdefault('ignore_ssl_errors'))
    }
}
kibana_options = list(client_options['kibana'].values())
elasticsearch_options = list(client_options['elasticsearch'].values())


def add_client(*client_type, add_to_ctx=True, add_func_arg=True):
    """Wrapper to add authed client."""
    from elasticsearch import Elasticsearch, ElasticsearchException
    from kibana import Kibana

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

                if add_func_arg:
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

                if add_func_arg:
                    kwargs['kibana_client'] = kibana_client
                if ctx and add_to_ctx:
                    ctx.obj['kibana'] = kibana_client

            return func(*args, **kwargs)

        return _wrapped

    return _wrapper
