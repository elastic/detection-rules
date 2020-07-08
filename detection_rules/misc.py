# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Misc support."""
import json
import os
import re
import time
import uuid

import click
import requests

from .utils import ROOT_DIR

_CONFIG = {}

LICENSE_HEADER = """
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.
""".strip()


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
    for key in dot_key.split('.')[:-1]:
        _dict = _dict.setdefault(key, {})

    if isinstance(_dict, dict):
        _dict[dot_key[-1]] = value
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
    r = requests.get('https://api.github.com/repos/elastic/kibana/branches?per_page=1000')
    branch_names = [b['name'] for b in r.json()]
    if branch not in branch_names:
        raise ValueError('branch "{}" does not exist in kibana'.format(branch))

    url = ('https://api.github.com/repos/elastic/kibana/contents/x-pack/{legacy}plugins/siem/server/lib/'
           'detection_engine/rules/prepackaged_rules?ref={branch}')

    gh_rules = requests.get(url.format(legacy='', branch=branch)).json()

    # pre-7.8 the siem was under the legacy directory
    if isinstance(gh_rules, dict) and gh_rules.get('message', '') == 'Not Found':
        gh_rules = requests.get(url.format(legacy='legacy/', branch=branch)).json()

    return {os.path.splitext(r['name'])[0]: r['download_url'] for r in gh_rules if r['name'].endswith('.json')}


def get_kibana_rules(*rule_paths, branch='master', verbose=True):
    """Retrieve prepackaged rules from kibana repo."""
    if verbose:
        click.echo('Downloading rules from {} branch in kibana repo...'.format(branch))

    if rule_paths:
        rule_paths = [os.path.splitext(os.path.basename(p))[0] for p in rule_paths]
        return {n: requests.get(r).json() for n, r in get_kibana_rules_map(branch).items() if n in rule_paths}
    else:
        return {n: requests.get(r).json() for n, r in get_kibana_rules_map(branch).items()}


def parse_config():
    """Parse a default config file."""
    global _CONFIG

    if not _CONFIG:
        config_file = os.path.join(ROOT_DIR, '.siem-rules-cfg.json')

        if os.path.exists(config_file):
            with open(config_file) as f:
                _CONFIG = json.load(f)

            click.secho('Loaded config file: {}'.format(config_file), fg='yellow')

    return _CONFIG


def set_param_values(ctx, param, value):
    """Get value for defined key."""
    key = param.name
    config = parse_config()
    env_key = 'SR_' + key
    prompt = True if param.hide_input is not False else False

    if value:
        return value
    elif os.environ.get(env_key):
        return os.environ[env_key]
    elif config.get(key):
        return config[key]
    elif prompt:
        return click.prompt(key, default=param.default if not param.default else None, hide_input=param.hide_input,
                            show_default=True if param.default else False)
