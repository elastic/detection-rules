# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
"""Rule object."""
import json
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Literal, Union, Optional, List, Any
from uuid import uuid4

from marshmallow import ValidationError, validates_schema

from . import utils
from .mixins import MarshmallowDataclassMixin
from .rule_formatter import toml_write, nested_normalize
from .schemas import definitions
from .schemas import downgrade
from .utils import cached

_META_SCHEMA_REQ_DEFAULTS = {}


@dataclass(frozen=True)
class RuleMeta(MarshmallowDataclassMixin):
    """Data stored in a rule's [metadata] section of TOML."""
    creation_date: definitions.Date
    updated_date: definitions.Date
    deprecation_date: Optional[definitions.Date]

    # Optional fields
    beats_version: Optional[definitions.BranchVer]
    ecs_versions: Optional[List[definitions.BranchVer]]
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

    def validate_query(self, meta: RuleMeta) -> None:
        pass


@dataclass
class QueryValidator:
    query: str

    @property
    def ast(self) -> Any:
        raise NotImplementedError

    def validate(self, data: 'QueryRuleData', meta: RuleMeta) -> None:
        raise NotImplementedError()


@dataclass(frozen=True)
class QueryRuleData(BaseRuleData):
    """Specific fields for query event types."""
    type: Literal["query"]

    index: Optional[List[str]]
    query: str
    language: definitions.FilterLanguages

    @cached_property
    def validator(self) -> Optional[QueryValidator]:
        if self.language == "kuery":
            return KQLValidator(self.query)
        elif self.language == "eql":
            return EQLValidator(self.query)

    def validate_query(self, meta: RuleMeta) -> None:
        validator = self.validator
        if validator is not None:
            return validator.validate(self, meta)

    @cached_property
    def ast(self):
        validator = self.validator
        if validator is not None:
            return validator.ast


@dataclass(frozen=True)
class MachineLearningRuleData(BaseRuleData):
    type: Literal["machine_learning"]

    anomaly_threshold: int
    machine_learning_job_id: str


@dataclass(frozen=True)
class ThresholdQueryRuleData(QueryRuleData):
    """Specific fields for query event types."""

    @dataclass(frozen=True)
    class ThresholdMapping(MarshmallowDataclassMixin):
        @dataclass(frozen=True)
        class ThresholdCardinality:
            field: str
            value: definitions.ThresholdValue

        field: List[definitions.NonEmptyStr]
        value: definitions.ThresholdValue
        cardinality: Optional[ThresholdCardinality]

    type: Literal["threshold"]
    threshold: ThresholdMapping


@dataclass(frozen=True)
class EQLRuleData(QueryRuleData):
    """EQL rules are a special case of query rules."""
    type: Literal["eql"]
    language: Literal["eql"]


@dataclass(frozen=True)
class ThreatMatchRuleData(QueryRuleData):
    """Specific fields for indicator (threat) match rule."""

    @dataclass(frozen=True)
    class Entries:

        @dataclass(frozen=True)
        class ThreatMapEntry:
            field: definitions.NonEmptyStr
            type: Literal["mapping"]
            value: definitions.NonEmptyStr

        entries: List[ThreatMapEntry]

    type: Literal["threat_match"]

    concurrent_searches: Optional[definitions.PositiveInteger]
    items_per_search: Optional[definitions.PositiveInteger]

    threat_mapping: List[Entries]
    threat_filters: Optional[List[dict]]
    threat_query: Optional[str]
    threat_language: Optional[definitions.FilterLanguages]
    threat_index: List[str]
    threat_indicator_path: Optional[str]

    def validate_query(self, meta: RuleMeta) -> None:
        super(ThreatMatchRuleData, self).validate_query(meta)

        if self.threat_query:
            if not self.threat_language:
                raise ValidationError('`threat_language` required when a `threat_query` is defined')

            if self.threat_language == "kuery":
                threat_query_validator = KQLValidator(self.threat_query)
            elif self.threat_language == "eql":
                threat_query_validator = EQLValidator(self.threat_query)
            else:
                return

            threat_query_validator.validate(self, meta)


# All of the possible rule types
AnyRuleData = Union[QueryRuleData, EQLRuleData, MachineLearningRuleData, ThresholdQueryRuleData, ThreatMatchRuleData]


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

    def lock_info(self) -> dict:
        return {"rule_name": self.name, "sha256": self.sha256(), "version": self.autobumped_version}

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

        return data.validate_query(metadata)

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


@dataclass
class TOMLRule:
    contents: TOMLRuleContents = field(hash=True)
    path: Optional[Path] = None
    gh_pr: Any = field(hash=False, compare=False, default=None, repr=None)

    @property
    def id(self):
        return self.contents.id

    @property
    def name(self):
        return self.contents.data.name

    def get_asset(self) -> dict:
        """Generate the relevant fleet compatible asset."""
        return {"id": self.id, "attributes": self.contents.to_api_format(), "type": definitions.SAVED_OBJECT_TYPE}

    def save_toml(self):
        assert self.path is not None, f"Can't save rule {self.name} (self.id) without a path"
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


# avoid a circular import
from .rule_validators import KQLValidator, EQLValidator  # noqa: E402
