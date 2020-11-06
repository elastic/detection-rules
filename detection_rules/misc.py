# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Misc support."""
import json
import os
import re
import time
import uuid
from functools import wraps

import click
import requests

from .utils import add_params, cached, get_path

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
        raise ClientError(message, original_error=type(exc).__name__)


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


client_options = {
    'kibana': {
        'kibana_url': click.Option(['--kibana-url'], default=getdefault('kibana_url')),
        'cloud_id': click.Option(['--cloud-id'], default=getdefault('cloud_id')),
        'kibana_user': click.Option(['--kibana-user', '-ku'], default=getdefault('kibana_user')),
        'kibana_password': click.Option(['--kibana-password', '-kp'], default=getdefault('kibana_password')),
        'space': click.Option(['--space'], default=None, help='Kibana space')
    },
    'elasticsearch': {
        'elasticsearch_url': click.Option(['--elasticsearch-url'], default=getdefault("elasticsearch_url")),
        'cloud_id': click.Option(['--cloud-id'], default=getdefault("cloud_id")),
        'es_user': click.Option(['--es-user', '-eu'], default=getdefault("es_user")),
        'es_password': click.Option(['--es-password', '-ep'], default=getdefault("es_password")),
        'timeout': click.Option(['--timeout', '-et'], default=60, help='Timeout for elasticsearch client')
    }
}
kibana_options = list(client_options['kibana'].values())
elasticsearch_options = list(client_options['elasticsearch'].values())


def add_client(*client_type, add_to_ctx=True):
    """Wrapper to add authed client."""
    from .eswrap import get_authed_es_client
    from .kbwrap import get_authed_kibana_client

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
            es_client_args = {k: kwargs.pop(k) for k in client_ops_keys.get('elasticsearch', [])}
            #                                      shared args like cloud_id
            kibana_client_args = {k: kwargs.pop(k, es_client_args.get(k)) for k in client_ops_keys.get('kibana', [])}

            if 'elasticsearch' in client_type:
                elasticsearch_client = get_authed_es_client(use_ssl=True, **es_client_args)
                kwargs['elasticsearch_client'] = elasticsearch_client
                if ctx and add_to_ctx:
                    ctx.obj['es'] = elasticsearch_client

            if 'kibana' in client_type:
                kibana_client = get_authed_kibana_client(kibana_client_args)
                kwargs['kibana_client'] = kibana_client
                if ctx and add_to_ctx:
                    ctx.obj['kibana'] = kibana_client

            return func(*args, **kwargs)

        return _wrapped

    return _wrapper
