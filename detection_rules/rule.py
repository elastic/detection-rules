# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.
"""Rule object."""
import base64
import copy
import hashlib
import json
import os

import click
import kql

from . import ecs, beats
from .attack import TACTICS, build_threat_map_entry, technique_lookup
from .rule_formatter import nested_normalize, toml_write
from .schema import RULE_TYPES, metadata_schema, schema_validate, get_schema
from .utils import get_path, clear_caches, cached


RULES_DIR = get_path("rules")
_META_SCHEMA_REQ_DEFAULTS = {}


class Rule(object):
    """Rule class containing all the information about a rule."""

    def __init__(self, path, contents):
        """Create a Rule from a toml management format."""
        self.path = os.path.abspath(path)
        self.contents = contents.get('rule', contents)
        self.metadata = self.set_metadata(contents.get('metadata', contents))

        self.formatted_rule = copy.deepcopy(self.contents).get('query', None)

        self.validate()
        self.unoptimized_query = self.contents.get('query')
        self._original_hash = self.get_hash()

    def __str__(self):
        return 'name={}, path={}, query={}'.format(self.name, self.path, self.query)

    def __repr__(self):
        return '{}(path={}, contents={})'.format(type(self).__name__, repr(self.path), repr(self.contents))

    def __eq__(self, other):
        if type(self) == type(other):
            return self.get_hash() == other.get_hash()
        return False

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash(self.get_hash())

    def copy(self):
        return Rule(path=self.path, contents={'rule': self.contents.copy(), 'metadata': self.metadata.copy()})

    @property
    def id(self):
        return self.contents.get("rule_id")

    @property
    def name(self):
        return self.contents.get("name")

    @property
    def query(self):
        return self.contents.get('query')

    @property
    def parsed_kql(self):
        if self.query and self.contents['language'] == 'kuery':
            return kql.parse(self.query)

    @property
    def filters(self):
        return self.contents.get('filters')

    @property
    def ecs_version(self):
        return sorted(self.metadata.get('ecs_version', []))

    @property
    def flattened_contents(self):
        return dict(self.contents, **self.metadata)

    @property
    def type(self):
        return self.contents.get('type')

    def to_eql(self):
        if self.query and self.contents['language'] == 'kuery':
            return kql.to_eql(self.query)

    @staticmethod
    @cached
    def get_meta_schema_required_defaults():
        """Get the default values for required properties in the metadata schema."""
        required = [v for v in metadata_schema['required']]
        properties = {k: v for k, v in metadata_schema['properties'].items() if k in required}
        return {k: v.get('default') or [v['items']['default']] for k, v in properties.items()}

    def set_metadata(self, contents):
        """Parse metadata fields and set missing required fields to the default values."""
        metadata = {k: v for k, v in contents.items() if k in metadata_schema['properties']}
        defaults = self.get_meta_schema_required_defaults().copy()
        defaults.update(metadata)
        return defaults

    def rule_format(self, formatted_query=True):
        """Get the contents in rule format."""
        contents = self.contents.copy()
        if formatted_query:
            if self.formatted_rule:
                contents['query'] = self.formatted_rule
        return {'metadata': self.metadata, 'rule': contents}

    def normalize(self, indent=2):
        """Normalize the (api only) contents and return a serialized dump of it."""
        return json.dumps(nested_normalize(self.contents), sort_keys=True, indent=indent)

    def get_path(self):
        """Wrapper around getting path."""
        if not self.path:
            raise ValueError('path not set for rule: \n\t{}'.format(self))

        return self.path

    def needs_save(self):
        """Determines if the rule was changed from original or was never saved."""
        return self._original_hash != self.get_hash()

    def bump_version(self):
        """Bump the version of the rule."""
        self.contents['version'] += 1

    def validate(self, as_rule=False, versioned=False):
        """Validate against a rule schema, query schema, and linting."""
        self.normalize()

        if as_rule:
            schema_validate(self.rule_format(), as_rule=True)
        else:
            schema_validate(self.contents, versioned=versioned)

        if self.query and self.contents['language'] == 'kuery':
            ecs_versions = self.metadata.get('ecs_version')
            indexes = self.contents.get("index", [])
            self._validate_kql(ecs_versions, indexes, self.query, self.name)

    @staticmethod
    @cached
    def _validate_kql(ecs_versions, indexes, query, name):
        # validate against all specified schemas or the latest if none specified
        parsed = kql.parse(query)
        beat_types = [index.split("-")[0] for index in indexes if "beat-*" in index]
        beat_schema = beats.get_schema_for_query(parsed, beat_types) if beat_types else None

        if not ecs_versions:
            kql.parse(query, schema=ecs.get_kql_schema(indexes=indexes, beat_schema=beat_schema))
        else:
            for version in ecs_versions:
                try:
                    schema = ecs.get_kql_schema(version=version, indexes=indexes, beat_schema=beat_schema)
                except KeyError:
                    raise KeyError(
                        'Unknown ecs schema version: {} in rule {}.\n'
                        'Do you need to update schemas?'.format(version, name))

                try:
                    kql.parse(query, schema=schema)
                except kql.KqlParseError as exc:
                    message = exc.error_msg
                    trailer = None
                    if "Unknown field" in message and beat_types:
                        trailer = "\nTry adding event.module and event.dataset to specify beats module"

                    raise kql.KqlParseError(exc.error_msg, exc.line, exc.column, exc.source,
                                            len(exc.caret.lstrip()), trailer=trailer)

    def save(self, new_path=None, as_rule=False, verbose=False):
        """Save as pretty toml rule file as toml."""
        path, _ = os.path.splitext(new_path or self.get_path())
        path += '.toml' if as_rule else '.json'

        if as_rule:
            toml_write(self.rule_format(), path)
        else:
            with open(path, 'w', newline='\n') as f:
                json.dump(self.contents, f, sort_keys=True, indent=2)
                f.write('\n')

        if verbose:
            print('Rule {} saved to {}'.format(self.name, path))

    def get_hash(self):
        """Get a standardized hash of a rule to consistently check for changes."""
        contents = base64.b64encode(json.dumps(self.contents, sort_keys=True).encode('utf-8'))
        return hashlib.sha256(contents).hexdigest()

    @classmethod
    def build(cls, path=None, rule_type=None, required_only=True, save=True, **kwargs):
        """Build a rule from data and prompts."""
        from .misc import schema_prompt
        # from .rule_loader import rta_mappings

        kwargs = copy.deepcopy(kwargs)

        while rule_type not in RULE_TYPES:
            rule_type = click.prompt('Rule type ({})'.format(', '.join(RULE_TYPES)))

        schema = get_schema(rule_type)
        props = schema['properties']
        opt_reqs = schema.get('required', [])
        contents = {}
        skipped = []

        for name, options in props.items():

            if name == 'type':
                contents[name] = rule_type
                continue

            # these are set at package release time
            if name == 'version':
                continue

            if required_only and name not in opt_reqs:
                continue

            # build this from technique ID
            if name == 'threat':
                threat_map = []

                while click.confirm('add mitre tactic?'):
                    tactic = schema_prompt('mitre tactic name', type='string', enum=TACTICS, required=True)
                    technique_ids = schema_prompt(f'technique IDs for {tactic}', type='array', required=True,
                                                  enum=list(technique_lookup))

                    try:
                        threat_map.append(build_threat_map_entry(tactic, *technique_ids))
                    except KeyError as e:
                        click.secho(f'Unknown ID: {e.args[0]}')
                        continue

                if len(threat_map) > 0:
                    contents[name] = threat_map
                continue

            if name == 'threshold':
                contents[name] = {n: schema_prompt(f'threshold {n}', required=n in options['required'], **opts)
                                  for n, opts in options['properties'].items()}
                continue

            if kwargs.get(name):
                contents[name] = schema_prompt(kwargs.pop(name))
                continue

            result = schema_prompt(name, required=name in opt_reqs, **options)

            if result:
                if name not in opt_reqs and result == options.get('default', ''):
                    skipped.append(name)
                    continue

                contents[name] = result

        metadata = {}
        ecs_version = schema_prompt('ecs_version', required=False, value=None,
                                    **metadata_schema['properties']['ecs_version'])
        if ecs_version:
            metadata['ecs_version'] = ecs_version

        # validate before creating
        schema_validate(contents)

        suggested_path = os.path.join(RULES_DIR, contents['name'])  # TODO: UPDATE BASED ON RULE STRUCTURE
        path = os.path.realpath(path or input('File path for rule [{}]: '.format(suggested_path)) or suggested_path)

        rule = None

        try:
            rule = cls(path, {'rule': contents, 'metadata': metadata})
        except kql.KqlParseError as e:
            if e.error_msg == 'Unknown field':
                warning = ('If using a non-ECS field, you must update "ecs{}.non-ecs-schema.json" under `beats` or '
                           '`legacy-endgame` (Non-ECS fields should be used minimally).'.format(os.path.sep))
                click.secho(e.args[0], fg='red', err=True)
                click.secho(warning, fg='yellow', err=True)
                click.pause()

            # if failing due to a query, loop until resolved or terminated
            while True:
                try:
                    contents['query'] = click.edit(contents['query'], extension='.eql')
                    rule = cls(path, {'rule': contents, 'metadata': metadata})
                except kql.KqlParseError as e:
                    click.secho(e.args[0], fg='red', err=True)
                    click.pause()

                    if e.error_msg.startswith("Unknown field"):
                        # get the latest schema for schema errors
                        clear_caches()
                        ecs.get_kql_schema(indexes=contents.get("index", []))
                    continue

                break

        if save:
            rule.save(verbose=True, as_rule=True)

        if skipped:
            print('Did not set the following values because they are un-required when set to the default value')
            print(' - {}'.format('\n - '.join(skipped)))

        # rta_mappings.add_rule_to_mapping_file(rule)
        # click.echo('Placeholder added to rule-mapping.yml')

        return rule
