# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
"""Rule object."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4

import eql

import kql
from . import ecs, beats
from .rule_formatter import nested_normalize, toml_write
from .schemas import CurrentSchema, TomlMetadata, downgrade
from .utils import get_path, cached

RULES_DIR = get_path("rules")
_META_SCHEMA_REQ_DEFAULTS = {}


class Rule(object):
    """Rule class containing all the information about a rule."""

    def __init__(self, path, contents):
        """Create a Rule from a toml management format."""
        self.path = os.path.abspath(path)
        self.contents = contents.get('rule', contents)
        self.metadata = contents.get('metadata', self.set_metadata(contents))

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

    def copy(self) -> 'Rule':
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
    def parsed_query(self):
        if self.query:
            if self.contents['language'] == 'kuery':
                return kql.parse(self.query)
            elif self.contents['language'] == 'eql':
                # TODO: remove once py-eql supports ipv6 for cidrmatch
                with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
                    return eql.parse_query(self.query)

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

    @property
    def unique_fields(self):
        parsed = self.parsed_query
        if parsed is not None:
            return list(set(str(f) for f in parsed if isinstance(f, (eql.ast.Field, kql.ast.Field))))

    def to_eql(self):
        if self.query and self.contents['language'] == 'kuery':
            return kql.to_eql(self.query)

    def get_flat_mitre(self):
        """Get flat lists of tactic and technique info."""
        tactic_names = []
        tactic_ids = []
        technique_ids = set()
        technique_names = set()
        sub_technique_ids = set()
        sub_technique_names = set()

        for entry in self.contents.get('threat', []):
            tactic_names.append(entry['tactic']['name'])
            tactic_ids.append(entry['tactic']['id'])

            for technique in entry.get('technique', []):
                technique_names.add(technique['name'])
                technique_ids.add(technique['id'])
                sub_technique = technique.get('subtechnique', [])

                sub_technique_ids.update(st['id'] for st in sub_technique)
                sub_technique_names.update(st['name'] for st in sub_technique)

        flat = {
            'tactic_names': sorted(tactic_names),
            'tactic_ids': sorted(tactic_ids),
            'technique_names': sorted(technique_names),
            'technique_ids': sorted(technique_ids),
            'sub_technique_names': sorted(sub_technique_names),
            'sub_technique_ids': sorted(sub_technique_ids)
        }
        return flat

    @classmethod
    def get_unique_query_fields(cls, rule_contents):
        """Get a list of unique fields used in a rule query from rule contents."""
        query = rule_contents.get('query')
        language = rule_contents.get('language')
        if language in ('kuery', 'eql'):
            # TODO: remove once py-eql supports ipv6 for cidrmatch
            with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
                parsed = kql.parse(query) if language == 'kuery' else eql.parse_query(query)

            return sorted(set(str(f) for f in parsed if isinstance(f, (eql.ast.Field, kql.ast.Field))))

    @staticmethod
    @cached
    def get_meta_schema_required_defaults():
        """Get the default values for required properties in the metadata schema."""
        required = [v for v in TomlMetadata.get_schema()['required']]
        properties = {k: v for k, v in TomlMetadata.get_schema()['properties'].items() if k in required}
        return {k: v.get('default') or [v['items']['default']] for k, v in properties.items()}

    def set_metadata(self, contents):
        """Parse metadata fields and set missing required fields to the default values."""
        metadata = {k: v for k, v in contents.items() if k in TomlMetadata.get_schema()['properties']}
        defaults = self.get_meta_schema_required_defaults().copy()
        defaults.update(metadata)
        return defaults

    @staticmethod
    def _add_empty_attack_technique(contents: dict = None):
        """Add empty array to ATT&CK technique threat mapping."""
        threat = contents.get('threat', [])

        if threat:
            new_threat = []

            for entry in contents.get('threat', []):
                if 'technique' not in entry:
                    new_entry = entry.copy()
                    new_entry['technique'] = []
                    new_threat.append(new_entry)
                else:
                    new_threat.append(entry)

            contents['threat'] = new_threat

        return contents

    def _run_build_time_transforms(self, contents):
        """Apply changes to rules at build time for rule payload."""
        self._add_empty_attack_technique(contents)
        return contents

    def rule_format(self, formatted_query=True):
        """Get the contents and metadata in rule format."""
        contents = self.contents.copy()
        if formatted_query:
            if self.formatted_rule:
                contents['query'] = self.formatted_rule
        return {'metadata': self.metadata, 'rule': contents}

    def detailed_format(self, add_missing_defaults=True, **additional_details):
        """Get the rule with expanded details."""
        from .rule_loader import get_non_required_defaults_by_type

        rule = self.rule_format().copy()

        if add_missing_defaults:
            non_required_defaults = get_non_required_defaults_by_type(self.type)
            rule['rule'].update({k: v for k, v in non_required_defaults.items() if k not in rule['rule']})

        rule['details'] = {
            'flat_mitre': self.get_flat_mitre(),
            'relative_path': str(Path(self.path).resolve().relative_to(RULES_DIR)),
            'unique_fields': self.unique_fields,

        }
        rule['details'].update(**additional_details)
        return rule

    def normalize(self, indent=2):
        """Normalize the (api only) contents and return a serialized dump of it."""
        return json.dumps(nested_normalize(self.contents, eql_rule=self.type == 'eql'), sort_keys=True, indent=indent)

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

    def validate(self, as_rule=False, versioned=False, query=True):
        """Validate against a rule schema, query schema, and linting."""
        self.normalize()

        if as_rule:
            schema_cls = CurrentSchema.toml_schema()
            contents = self.rule_format()
        elif versioned:
            schema_cls = CurrentSchema.versioned()
            contents = self.contents
        else:
            schema_cls = CurrentSchema
            contents = self.contents

        schema_cls.validate(contents, role=self.type)

        skip_query_validation = self.metadata['maturity'] in ('experimental', 'development') and \
            self.metadata.get('query_schema_validation') is False

        if query and self.query is not None and not skip_query_validation:
            ecs_versions = self.metadata.get('ecs_version', [ecs.get_max_version()])
            beats_version = self.metadata.get('beats_version', beats.get_max_version())
            indexes = self.contents.get("index", [])

            if self.contents['language'] == 'kuery':
                self._validate_kql(ecs_versions, beats_version, indexes, self.query, self.name)

            if self.contents['language'] == 'eql':
                self._validate_eql(ecs_versions, beats_version, indexes, self.query, self.name)

    @staticmethod
    @cached
    def _validate_eql(ecs_versions, beats_version, indexes, query, name):
        # validate against all specified schemas or the latest if none specified
        # TODO: remove once py-eql supports ipv6 for cidrmatch
        with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
            parsed = eql.parse_query(query)

        beat_types = [index.split("-")[0] for index in indexes if "beat-*" in index]
        beat_schema = beats.get_schema_from_eql(parsed, beat_types, version=beats_version) if beat_types else None

        ecs_versions = ecs_versions or [ecs_versions]
        schemas = []

        for version in ecs_versions:
            try:
                schemas.append(ecs.get_kql_schema(indexes=indexes, beat_schema=beat_schema, version=version))
            except KeyError:
                raise KeyError('Unknown ecs schema version: {} in rule {}.\n'
                               'Do you need to update schemas?'.format(version, name)) from None

        for schema in schemas:
            try:
                # TODO: remove once py-eql supports ipv6 for cidrmatch
                with ecs.KqlSchema2Eql(schema), eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
                    eql.parse_query(query)

            except eql.EqlTypeMismatchError:
                raise

            except eql.EqlParseError as exc:
                message = exc.error_msg
                trailer = None
                if "Unknown field" in message and beat_types:
                    trailer = "\nTry adding event.module or event.dataset to specify beats module"

                raise type(exc)(exc.error_msg, exc.line, exc.column, exc.source,
                                len(exc.caret.lstrip()), trailer=trailer) from None

    @staticmethod
    @cached
    def _validate_kql(ecs_versions, beats_version, indexes, query, name):
        # validate against all specified schemas or the latest if none specified
        parsed = kql.parse(query)
        beat_types = [index.split("-")[0] for index in indexes if "beat-*" in index]
        beat_schema = beats.get_schema_from_kql(parsed, beat_types, version=beats_version) if beat_types else None

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
                        trailer = "\nTry adding event.module or event.dataset to specify beats module"

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
                json.dump(self.get_payload(), f, sort_keys=True, indent=2)
                f.write('\n')

        if verbose:
            print('Rule {} saved to {}'.format(self.name, path))

    @classmethod
    def dict_hash(cls, contents, versioned=True):
        """Get hash from rule contents."""
        if not versioned:
            contents.pop('version', None)

        contents = base64.b64encode(json.dumps(contents, sort_keys=True).encode('utf-8'))
        return hashlib.sha256(contents).hexdigest()

    def get_hash(self):
        """Get a standardized hash of a rule to consistently check for changes."""
        return self.dict_hash(self.get_payload())

    def get_version(self):
        """Get the version of the rule."""
        from .packaging import load_versions

        rules_versions = load_versions()

        if self.id in rules_versions:
            version_info = rules_versions[self.id]
            version = version_info['version']
            return version + 1 if self.get_hash() != version_info['sha256'] else version
        else:
            return 1

    def get_payload(self, include_version=False, replace_id=False, embed_metadata=False, target_version=None):
        """Get rule as uploadable/API-compatible payload."""
        from uuid import uuid4
        from .schemas import downgrade

        payload = self._run_build_time_transforms(self.contents.copy())

        if include_version:
            payload['version'] = self.get_version()

        if embed_metadata:
            meta = payload.setdefault("meta", {})
            meta["original"] = dict(id=self.id, **self.metadata)

        if replace_id:
            payload["rule_id"] = str(uuid4())

        if target_version:
            payload = downgrade(payload, target_version)

        return payload


def downgrade_contents_from_rule(rule: Rule, target_version: str) -> dict:
    """Generate the downgraded contents from a rule."""
    payload = rule.contents.copy()
    meta = payload.setdefault("meta", {})
    meta["original"] = dict(id=rule.id, **rule.metadata)
    payload["rule_id"] = str(uuid4())
    payload = downgrade(payload, target_version)
    return payload
