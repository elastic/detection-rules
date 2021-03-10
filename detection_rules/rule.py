# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
"""Rule object."""
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Union, Optional, List
from uuid import uuid4

import eql
from marshmallow import validates_schema

import kql
from . import ecs, beats, utils
from .rule_formatter import toml_write
from .schemas import TomlMetadata, downgrade
from .schemas import definitions
from .utils import get_path, cached

RULES_DIR = get_path("rules")
_META_SCHEMA_REQ_DEFAULTS = {}


@dataclass(frozen=True)
class RuleMeta:
    """Data stored in a rule's [metadata] section of TOML."""
    creation_date: str
    updated_date: str

    # Optional fields
    beats_version: Optional[definitions.SemVer]
    ecs_versions: Optional[List[definitions.SemVer]]
    comments: Optional[str]
    maturity: Optional[definitions.Maturity]
    os_type_list: Optional[List[definitions.OSType]]
    query_schema_validation: Optional[bool]
    related_endpoint_rules: Optional[List[str]]


@dataclass(frozen=True)
class BaseThreatEntry:
    id: str
    name: str
    reference: str


@dataclass(frozen=True)
class SubTechnique(BaseThreatEntry):
    """Mapping to threat subtechnique."""


@dataclass(frozen=True)
class Technique(BaseThreatEntry):
    """Mapping to threat subtechnique."""
    # subtechniques are stored at threat[].technique.subtechnique[]
    subtechnique: Optional[List[SubTechnique]]


@dataclass(frozen=True)
class Tactic(BaseThreatEntry):
    """Mapping to a threat tactic."""


@dataclass(frozen=True)
class ThreatMapping:
    """Mapping to a threat framework."""
    framework: Literal["MITRE ATT&CK"]
    tactic: Tactic
    technique: Optional[List[Technique]]

    @staticmethod
    def flatten(threat_mappings: Optional[List]) -> 'FlatThreatMapping':
        """Get flat lists of tactic and technique info."""
        tactic_names = []
        tactic_ids = []
        technique_ids = set()
        technique_names = set()
        sub_technique_ids = set()
        sub_technique_names = set()

        for entry in (threat_mappings or []):
            tactic_names.append(entry.tactic.name)
            tactic_ids.append(entry.tactic.id)

            for technique in (entry.technique or []):
                technique_names.add(technique.name)
                technique_ids.add(technique.id)

                for subtechnique in (technique.subtechnique or []):
                    sub_technique_ids.update(subtechnique.id)
                    sub_technique_names.update(subtechnique.name)

        return FlatThreatMapping(
            tactic_names=sorted(tactic_names),
            tactic_ids=sorted(tactic_ids),
            technique_names=sorted(technique_names),
            technique_ids=sorted(technique_ids),
            sub_technique_names=sorted(sub_technique_names),
            sub_technique_ids=sorted(sub_technique_ids)
        )


@dataclass(frozen=True)
class RiskScoreMapping:
    field: str
    operator: Optional[definitions.Operator]
    value: Optional[str]


@dataclass(frozen=True)
class SeverityMapping:
    field: str
    operator: Optional[definitions.Operator]
    value: Optional[str]
    severity: Optional[str]


@dataclass(frozen=True)
class FlatThreatMapping:
    tactic_names: List[str]
    tactic_ids: List[str]
    technique_names: List[str]
    technique_ids: List[str]
    sub_technique_names: List[str]
    sub_technique_ids: List[str]


@dataclass(frozen=True)
class BaseRuleData:
    actions: Optional[list]
    author: List[str]
    building_block_type: Optional[str]
    description: Optional[str]
    enabled: Optional[bool]
    exceptions_list: Optional[list]
    license: str
    false_positives: Optional[List[str]]
    filters: Optional[List[dict]]
    # trailing `_` required since `from` is a reserved word in python
    from_: Optional[str] = field(metadata=dict(data_key="from"))

    interval: Optional[definitions.Interval]
    max_signals: Optional[definitions.MaxSignals]
    meta: Optional[dict]
    name: str
    note: Optional[definitions.Markdown]
    # can we remove this comment?
    # explicitly NOT allowed!
    # output_index: Optional[str]
    references: Optional[List[str]]
    risk_score: definitions.RiskScore
    risk_score_mapping: Optional[List[RiskScoreMapping]]
    rule_id: definitions.UUIDString
    rule_name_override: Optional[str]
    severity_mapping: Optional[List[SeverityMapping]]
    severity: Literal['low', 'medium', 'high', 'critical']
    tags: Optional[List[str]]
    throttle: Optional[str]
    timeline_id: Optional[str]
    timeline_title: Optional[str]
    timestamp_override: Optional[str]
    to: Optional[str]
    type: Literal[definitions.RuleType]
    threat: Optional[List[ThreatMapping]]


@dataclass(frozen=True)
class BaseQueryRuleData(BaseRuleData):
    """Specific fields for query event types."""
    type: Literal["query"]

    index: Optional[List[str]]
    query: str
    language: str

    @property
    def parsed_query(self) -> Optional[object]:
        return None


@dataclass(frozen=True)
class KQLRuleData(BaseQueryRuleData):
    """Specific fields for query event types."""
    language: Literal["kuery"]

    @property
    def parsed_query(self) -> kql.ast.Expression:
        return kql.parse(self.query)

    @property
    def unique_fields(self):
        return list(set(str(f) for f in self.parsed_query if isinstance(f, kql.ast.Field)))

    def to_eql(self) -> eql.ast.Expression:
        return kql.to_eql(self.query)

    def validate_query(self, beats_version: str, ecs_versions: List[str]):
        """Static method to validate the query, called from the parent which contains [metadata] information."""
        indexes = self.index or []
        parsed = self.parsed_query

        beat_types = [index.split("-")[0] for index in indexes if "beat-*" in index]
        beat_schema = beats.get_schema_from_kql(parsed, beat_types, version=beats_version) if beat_types else None

        if not ecs_versions:
            kql.parse(self.query, schema=ecs.get_kql_schema(indexes=indexes, beat_schema=beat_schema))
        else:
            for version in ecs_versions:
                schema = ecs.get_kql_schema(version=version, indexes=indexes, beat_schema=beat_schema)

                try:
                    kql.parse(self.query, schema=schema)
                except kql.KqlParseError as exc:
                    message = exc.error_msg
                    trailer = None
                    if "Unknown field" in message and beat_types:
                        trailer = "\nTry adding event.module or event.dataset to specify beats module"

                    raise kql.KqlParseError(exc.error_msg, exc.line, exc.column, exc.source,
                                            len(exc.caret.lstrip()), trailer=trailer) from None


@dataclass(frozen=True)
class LuceneRuleData(BaseQueryRuleData):
    """Specific fields for query event types."""
    language: Literal["lucene"]


@dataclass(frozen=True)
class MachineLearningRuleData(BaseRuleData):
    type: Literal["machine_learning"]

    anomaly_threshold: int
    machine_learning_job_id: str


@dataclass(frozen=True)
class ThresholdQueryRuleData(BaseQueryRuleData):
    """Specific fields for query event types."""

    @dataclass(frozen=True)
    class ThresholdMapping:
        @dataclass(frozen=True)
        class ThresholdCardinality:
            field: str
            value: definitions.ThresholdValue

        field: List[str]
        value: definitions.ThresholdValue
        cardinality: Optional[ThresholdCardinality]

    type: Literal["threshold"]
    language: Literal["kuery", "lucene"]
    threshold: ThresholdMapping


@dataclass(frozen=True)
class EQLRuleData(BaseQueryRuleData):
    """EQL rules are a special case of query rules."""
    type: Literal["eql"]

    @property
    def parsed_query(self) -> kql.ast.Expression:
        with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
            return eql.parse_query(self.query)

    @property
    def unique_fields(self):
        return list(set(str(f) for f in self.parsed_query if isinstance(f, eql.ast.Field)))

    def validate_query(self, beats_version: str, ecs_versions: List[str]):
        """Validate an EQL query while checking TOMLRule."""
        # TODO: remove once py-eql supports ipv6 for cidrmatch
        # Or, unregister the cidrMatch function and replace it with one that doesn't validate against strict IPv4
        with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
            parsed = eql.parse_query(self.query)

        beat_types = [index.split("-")[0] for index in self.index or [] if "beat-*" in index]
        beat_schema = beats.get_schema_from_eql(parsed, beat_types, version=beats_version) if beat_types else None

        for version in ecs_versions:
            schema = ecs.get_kql_schema(indexes=self.index or [], beat_schema=beat_schema, version=version)

            try:
                # TODO: switch to custom cidrmatch that allows ipv6
                with ecs.KqlSchema2Eql(schema), eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
                    eql.parse_query(self.query)

            except eql.EqlTypeMismatchError:
                raise

            except eql.EqlParseError as exc:
                message = exc.error_msg
                trailer = None
                if "Unknown field" in message and beat_types:
                    trailer = "\nTry adding event.module or event.dataset to specify beats module"

                raise exc.__class__(exc.error_msg, exc.line, exc.column, exc.source,
                                    len(exc.caret.lstrip()), trailer=trailer) from None


# All of the possible rule types
AnyRuleData = Union[KQLRuleData, LuceneRuleData, MachineLearningRuleData, ThresholdQueryRuleData, EQLRuleData]


@dataclass(frozen=True)
class TOMLRuleContents:
    """Rule object which maps directly to the TOML layout."""
    metadata: RuleMeta
    data: AnyRuleData = field(metadata=dict(data_key="rule"))

    @property
    def id(self) -> definitions.UUIDString:
        return self.data.rule_id

    @property
    def name(self) -> str:
        return self.data.name

    @property
    def is_dirty(self) -> Optional[bool]:
        """Determine if the rule has changed since its version was locked."""
        from .packaging import load_versions

        rules_versions = load_versions()

        if self.id in rules_versions:
            version_info = rules_versions[self.id]
            version = version_info['version']
            return version

    @property
    def latest_version(self) -> Optional[int]:
        """Retrieve the latest known version of the rule."""
        from .packaging import load_versions

        rules_versions = load_versions()

        if self.id in rules_versions:
            version_info = rules_versions[self.id]
            version = version_info['version']
            return version

    @property
    def autobumped_version(self) -> Optional[int]:
        """Retrieve the current version of the rule, accounting for automatic increments."""
        version = self.latest_version
        if version is None:
            return 1

        return version + 1 if self.is_dirty else version

    @validates_schema
    def validate_query(self, value: dict, **kwargs):
        """Validate queries by calling into the validator for the relevant method."""
        data: AnyRuleData = value["data"]
        metadata: RuleMeta = value["metadata"]

        beats_version = metadata.beats_version or beats.get_max_version()
        ecs_versions = metadata.ecs_versions or [ecs.get_max_version()]

        # call into these validate methods
        if isinstance(data, (EQLRuleData, KQLRuleData)):
            if metadata.query_schema_validation is False:
                # Check the syntax only
                _ = data.parsed_query
            else:
                # otherwise, do a full schema validation
                data.validate_query(beats_version=beats_version, ecs_versions=ecs_versions)

    def flattened_dict(self) -> dict:
        flattened = dict()
        flattened.update(utils.dataclass_to_dict(self.data))
        flattened.update(utils.dataclass_to_dict(self.metadata))
        return flattened

    def to_api_format(self, include_version=True) -> dict:
        """Convert the TOML rule to the API format."""
        converted = utils.dataclass_to_dict(self.data)
        if include_version:
            converted["version"] = self.autobumped_version

        return converted

    @cached
    def sha256(self) -> str:
        # get the hash of the API dict with the version not included, otherwise it'll always be dirty.
        hashable_contents = self.to_api_format(include_version=False)
        return utils.dict_hash(hashable_contents)


@dataclass(frozen=True)
class TOMLRule:
    contents: TOMLRuleContents
    path: Path

    @property
    def id(self):
        return self.contents.id

    @property
    def name(self):
        return self.contents.data.name

    def save_toml(self):
        converted = utils.dataclass_to_dict(self.contents)
        converted.pop("path")
        toml_write(converted, str(self.path.absolute()))

    def save_json(self, path: Path, include_version: bool = True):
        with open(str(path.absolute()), 'w', newline='\n') as f:
            json.dump(self.contents.to_api_format(include_version=include_version), f, sort_keys=True, indent=2)
            f.write('\n')


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
#
#
# def rule_format(self, formatted_query=True):
#     """Get the contents and metadata in rule format."""
#     contents = self.contents.copy()
#     if formatted_query:
#         if self.formatted_rule:
#             contents['query'] = self.formatted_rule
#     return {'metadata': self.metadata, 'rule': contents}
#
#
# def detailed_format(self, add_missing_defaults=True, **additional_details):
#     """Get the rule with expanded details."""
#     from .rule_loader import get_non_required_defaults_by_type
#
#     rule = self.rule_format().copy()
#
#     if add_missing_defaults:
#         non_required_defaults = get_non_required_defaults_by_type(self.type)
#         rule['rule'].update({k: v for k, v in non_required_defaults.items() if k not in rule['rule']})
#
#     rule['details'] = {
#         'flat_mitre': self.get_flat_mitre(),
#         'relative_path': str(Path(self.path).resolve().relative_to(RULES_DIR)),
#         'unique_fields': self.unique_fields,
#
#     }
#     rule['details'].update(**additional_details)
#     return rule
# #
# #
# # def normalize(self, indent=2):
# #     """Normalize the (api only) contents and return a serialized dump of it."""
# #     return json.dumps(nested_normalize(self.contents, eql_rule=self.type == 'eql'), sort_keys=True, indent=indent)
# #
# #
# # def get_path(self):
# #     """Wrapper around getting path."""
# #     if not self.path:
# #         raise ValueError('path not set for rule: \n\t{}'.format(self))
# #
# #     return self.path
# #
# #
# # def needs_save(self):
# #     """Determines if the rule was changed from original or was never saved."""
# #     return self._original_hash != self.get_hash()
# #
# #
# # def bump_version(self):
# #     """Bump the version of the rule."""
# #     self.contents['version'] += 1
# #
# #
# # def rule_validate(self, as_rule=False, versioned=False, query=True):
# #     """Validate against a rule schema, query schema, and linting."""
# #     self.normalize()
# #
# #     if as_rule:
# #         schema_cls = CurrentSchema.toml_schema()
# #         contents = self.rule_format()
# #     elif versioned:
# #         schema_cls = CurrentSchema.versioned()
# #         contents = self.contents
# #     else:
# #         schema_cls = CurrentSchema
# #         contents = self.contents
# #
# #     schema_cls.validate(contents, role=self.type)
# #
# #     skip_query_validation = self.metadata['maturity'] in ('experimental', 'development') and \
# #         self.metadata.get('query_schema_validation') is False
# #
# #     if query and self.query is not None and not skip_query_validation:
# #         ecs_versions = self.metadata.get('ecs_version', [ecs.get_max_version()])
# #         beats_version = self.metadata.get('beats_version', beats.get_max_version())
# #         indexes = self.contents.get("index", [])
# #
# #         if self.contents['language'] == 'kuery':
# #             self._validate_kql(ecs_versions, beats_version, indexes, self.query, self.name)
# #
# #         if self.contents['language'] == 'eql':
# #             self._validate_eql(ecs_versions, beats_version, indexes, self.query, self.name)
# #
# #
# # def save(self, new_path=None, as_rule=False, verbose=False):
# #     """Save as pretty toml rule file as toml."""
# #     path, _ = os.path.splitext(new_path or self.get_path())
# #     path += '.toml' if as_rule else '.json'
# #
# #     if as_rule:
# #         toml_write(self.rule_format(), path)
# #     else:
# #         with open(path, 'w', newline='\n') as f:
# #             json.dump(self.get_payload(), f, sort_keys=True, indent=2)
# #             f.write('\n')
# #
# #     if verbose:
# #         print('Rule {} saved to {}'.format(self.name, path))
#
#
# def get_payload(self: TOMLRule, include_version=False, replace_id=False, embed_metadata=False, target_version=None):
#     """Get rule as uploadable/API-compatible payload."""
#     from uuid import uuid4
#     from .schemas import downgrade
#
#     payload = self._run_build_time_transforms(self.contents.copy())
#
#     if include_version:
#         payload['version'] = self.get_version()
#
#     if embed_metadata:
#         meta = payload.setdefault("meta", {})
#         meta["original"] = dict(id=self.id, **self.metadata)
#
#     if replace_id:
#         payload["rule_id"] = str(uuid4())
#
#     if target_version:
#         payload = downgrade(payload, target_version)
#
#     return payload


def downgrade_contents_from_rule(rule: TOMLRule, target_version: str) -> dict:
    """Generate the downgraded contents from a rule."""
    payload = rule.contents.to_api_format()
    meta = payload.setdefault("meta", {})
    meta["original"] = dict(id=rule.id, **utils.dataclass_to_dict(rule.contents.metadata))
    payload["rule_id"] = str(uuid4())
    payload = downgrade(payload, target_version)
    return payload
