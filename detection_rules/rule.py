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
from .mixins import MarshmallowDataclassMixin
from .rule_formatter import toml_write, nested_normalize
from .schemas import downgrade
from .schemas import definitions
from .utils import get_path, cached

RULES_DIR = get_path("rules")
_META_SCHEMA_REQ_DEFAULTS = {}


@dataclass(frozen=True)
class RuleMeta(MarshmallowDataclassMixin):
    """Data stored in a rule's [metadata] section of TOML."""
    creation_date: definitions.Date
    updated_date: definitions.Date
    deprecation_date: Optional[definitions.Date]

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
    reference: definitions.SubTechniqueURL


@dataclass(frozen=True)
class Technique(BaseThreatEntry):
    """Mapping to threat subtechnique."""
    # subtechniques are stored at threat[].technique.subtechnique[]
    reference: definitions.TechniqueURL
    subtechnique: Optional[List[SubTechnique]]


@dataclass(frozen=True)
class Tactic(BaseThreatEntry):
    """Mapping to a threat tactic."""
    reference: definitions.TacticURL


@dataclass(frozen=True)
class ThreatMapping(MarshmallowDataclassMixin):
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
class RiskScoreMapping(MarshmallowDataclassMixin):
    field: str
    operator: Optional[definitions.Operator]
    value: Optional[str]


@dataclass(frozen=True)
class SeverityMapping(MarshmallowDataclassMixin):
    field: str
    operator: Optional[definitions.Operator]
    value: Optional[str]
    severity: Optional[str]


@dataclass(frozen=True)
class FlatThreatMapping(MarshmallowDataclassMixin):
    tactic_names: List[str]
    tactic_ids: List[str]
    technique_names: List[str]
    technique_ids: List[str]
    sub_technique_names: List[str]
    sub_technique_ids: List[str]


@dataclass(frozen=True)
class BaseRuleData(MarshmallowDataclassMixin):
    actions: Optional[list]
    author: List[str]
    building_block_type: Optional[str]
    description: Optional[str]
    enabled: Optional[bool]
    exceptions_list: Optional[list]
    license: Optional[str]
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
    severity: definitions.Severity
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
    class ThresholdMapping(MarshmallowDataclassMixin):
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
class TOMLRuleContents(MarshmallowDataclassMixin):
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
            existing_sha256: str = version_info['sha256']
            return existing_sha256 != self.sha256()

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
            if metadata.query_schema_validation is False or metadata.maturity == "deprecated":
                # Check the syntax only
                _ = data.parsed_query
            else:
                # otherwise, do a full schema validation
                data.validate_query(beats_version=beats_version, ecs_versions=ecs_versions)

    def to_dict(self, strip_none_values=True) -> dict:
        dict_obj = super(TOMLRuleContents, self).to_dict(strip_none_values=strip_none_values)
        return nested_normalize(dict_obj)

    def flattened_dict(self) -> dict:
        flattened = dict()
        flattened.update(self.data.to_dict())
        flattened.update(self.metadata.to_dict())
        return flattened

    @staticmethod
    def _post_dict_transform(obj: dict) -> dict:
        """Transform the converted API in place before sending to Kibana."""

        # cleanup the whitespace in the rule
        obj = nested_normalize(obj, eql_rule=obj.get("language") == "eql")

        # fill in threat.technique so it's never missing
        for threat_entry in obj.get("threat", []):
            threat_entry.setdefault("technique", [])

        return obj

    def to_api_format(self, include_version=True) -> dict:
        """Convert the TOML rule to the API format."""
        converted = self.data.to_dict()
        if include_version:
            converted["version"] = self.autobumped_version

        converted = self._post_dict_transform(converted)

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
        converted = self.contents.to_dict()
        toml_write(converted, str(self.path.absolute()))

    def save_json(self, path: Path, include_version: bool = True):
        with open(str(path.absolute()), 'w', newline='\n') as f:
            json.dump(self.contents.to_api_format(include_version=include_version), f, sort_keys=True, indent=2)
            f.write('\n')


def downgrade_contents_from_rule(rule: TOMLRule, target_version: str) -> dict:
    """Generate the downgraded contents from a rule."""
    payload = rule.contents.to_api_format()
    meta = payload.setdefault("meta", {})
    meta["original"] = dict(id=rule.id, **rule.contents.metadata.to_dict())
    payload["rule_id"] = str(uuid4())
    payload = downgrade(payload, target_version)
    return payload
