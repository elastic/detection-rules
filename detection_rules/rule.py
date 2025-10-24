# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
"""Rule object."""

import copy
import dataclasses
import json
import os
import re
import time
import typing
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse
from uuid import uuid4

import eql  # type: ignore[reportMissingTypeStubs]
import kql  # type: ignore[reportMissingTypeStubs]
import marshmallow
from marko.block import Document as MarkoDocument
from marko.ext.gfm import gfm
from marshmallow import ValidationError, pre_load, validates_schema
from semver import Version

from . import beats, ecs, endgame, utils
from .config import load_current_package_version, parse_rules_config
from .esql import get_esql_query_event_dataset_integrations
from .esql_errors import EsqlSemanticError
from .integrations import (
    find_least_compatible_version,
    get_integration_schema_fields,
    load_integrations_manifests,
    load_integrations_schemas,
)
from .mixins import MarshmallowDataclassMixin, StackCompatMixin
from .rule_formatter import nested_normalize, toml_write
from .schemas import (
    SCHEMA_DIR,
    definitions,
    downgrade,
    get_min_supported_stack_version,
    get_stack_schemas,
    strip_non_public_fields,
)
from .schemas.stack_compat import get_restricted_fields
from .utils import PatchedTemplate, cached, convert_time_span, get_nested_value, set_nested_value
from .version_lock import VersionLock, loaded_version_lock

if typing.TYPE_CHECKING:
    from .remote_validation import RemoteValidator


MIN_FLEET_PACKAGE_VERSION = "7.13.0"
TIME_NOW = time.strftime("%Y/%m/%d")
RULES_CONFIG = parse_rules_config()
DEFAULT_PREBUILT_RULES_DIRS = RULES_CONFIG.rule_dirs
DEFAULT_PREBUILT_BBR_DIRS = RULES_CONFIG.bbr_rules_dirs
BYPASS_VERSION_LOCK = RULES_CONFIG.bypass_version_lock


BUILD_FIELD_VERSIONS = {
    "related_integrations": (Version.parse("8.3.0"), None),
    "required_fields": (Version.parse("8.3.0"), None),
    "setup": (Version.parse("8.3.0"), None),
}


@dataclass(kw_only=True)
class DictRule:
    """Simple object wrapper for raw rule dicts."""

    contents: dict[str, Any]
    path: Path | None = None

    @property
    def metadata(self) -> dict[str, Any]:
        """Metadata portion of TOML file rule."""
        return self.contents.get("metadata", {})

    @property
    def data(self) -> dict[str, Any]:
        """Rule portion of TOML file rule. Supports nested and flattened rule dictionaries"""
        return self.contents.get("data", {}) or self.contents or self.contents.get("rule", {})

    @property
    def id(self) -> str:
        """Get the rule ID. Supports nested and flattened rule dictionaries."""
        return self.data.get("rule_id") or self.data.get("rule", {}).get("rule_id")

    @property
    def name(self) -> str:
        """Get the rule name. Supports nested and flattened rule dictionaries"""
        return self.data.get("name") or self.data.get("rule", {}).get("name")

    def __hash__(self) -> int:
        """Get the hash of the rule."""
        return hash(self.id + self.name)

    def __repr__(self) -> str:
        """Get a string representation of the rule."""
        return f"Rule({self.name} {self.id})"


@dataclass(frozen=True, kw_only=True)
class RuleMeta(MarshmallowDataclassMixin):
    """Data stored in a rule's [metadata] section of TOML."""

    creation_date: definitions.Date
    updated_date: definitions.Date
    deprecation_date: definitions.Date | None = None

    # Optional fields
    bypass_bbr_timing: bool | None = None
    comments: str | None = None
    integration: str | list[str] | None = None
    maturity: definitions.Maturity | None = None
    min_stack_version: definitions.SemVer | None = None
    min_stack_comments: str | None = None
    os_type_list: list[definitions.OSType] | None = None
    query_schema_validation: bool | None = None
    related_endpoint_rules: list[str] | None = None
    promotion: bool | None = None

    # Extended information as an arbitrary dictionary
    extended: dict[str, Any] | None = None

    def get_validation_stack_versions(self) -> dict[str, dict[str, Any]]:
        """Get a dict of beats and ecs versions per stack release."""
        return get_stack_schemas(self.min_stack_version)


@dataclass(frozen=True, kw_only=True)
class RuleTransform(MarshmallowDataclassMixin):
    """Data stored in a rule's [transform] section of TOML."""

    # note (investigation guides) Markdown plugins
    # /elastic/kibana/tree/main/x-pack/plugins/security_solution/public/common/components/markdown_editor/plugins
    ##############################################

    # timelines out of scope at the moment

    @dataclass(frozen=True, kw_only=True)
    class OsQuery:
        label: str
        query: str
        ecs_mapping: dict[str, dict[Literal["field", "value"], str]] | None = None

    @dataclass(frozen=True, kw_only=True)
    class Investigate:
        @dataclass(frozen=True)
        class Provider:
            excluded: bool
            field: str
            queryType: definitions.InvestigateProviderQueryType
            value: str
            valueType: definitions.InvestigateProviderValueType

        label: str
        description: str | None = None
        providers: list[list[Provider]]
        relativeFrom: str | None = None
        relativeTo: str | None = None

    # these must be lists in order to have more than one. Their index in the list is how they will be referenced in the
    # note string templates
    osquery: list[OsQuery] | None = None
    investigate: list[Investigate] | None = None

    def render_investigate_osquery_to_string(self) -> dict[definitions.TransformTypes, list[str]]:
        obj = self.to_dict()

        rendered: dict[definitions.TransformTypes, list[str]] = {"osquery": [], "investigate": []}
        for plugin, entries in obj.items():
            for entry in entries:
                if plugin not in rendered:
                    raise ValueError(f"Unexpected field value: {plugin}")
                rendered[plugin].append(f"!{{{plugin}{json.dumps(entry, sort_keys=True, separators=(',', ':'))}}}")

        return rendered

    ##############################################


@dataclass(frozen=True)
class BaseThreatEntry:
    id: str
    name: str
    reference: str

    @pre_load
    def modify_url(self, data: dict[str, Any], **_: Any) -> dict[str, Any]:
        """Modify the URL to support MITRE ATT&CK URLS with and without trailing forward slash."""
        p = urlparse(data["reference"])  # type: ignore[reportUnknownVariableType]
        if p.scheme and not data["reference"].endswith("/"):  # type: ignore[reportUnknownMemberType]
            data["reference"] += "/"
        return data


@dataclass(frozen=True)
class SubTechnique(BaseThreatEntry):
    """Mapping to threat subtechnique."""

    reference: definitions.SubTechniqueURL


@dataclass(frozen=True, kw_only=True)
class Technique(BaseThreatEntry):
    """Mapping to threat subtechnique."""

    # subtechniques are stored at threat[].technique.subtechnique[]
    reference: definitions.TechniqueURL
    subtechnique: list[SubTechnique] | None = None


@dataclass(frozen=True)
class Tactic(BaseThreatEntry):
    """Mapping to a threat tactic."""

    reference: definitions.TacticURL


@dataclass(frozen=True, kw_only=True)
class ThreatMapping(MarshmallowDataclassMixin):
    """Mapping to a threat framework."""

    framework: Literal["MITRE ATT&CK"]
    tactic: Tactic
    technique: list[Technique] | None = None

    @staticmethod
    def flatten(threat_mappings: list["ThreatMapping"] | None) -> "FlatThreatMapping":
        """Get flat lists of tactic and technique info."""
        tactic_names: list[str] = []
        tactic_ids: list[str] = []
        technique_ids: set[str] = set()
        technique_names: set[str] = set()
        sub_technique_ids: set[str] = set()
        sub_technique_names: set[str] = set()

        for entry in threat_mappings or []:
            tactic_names.append(entry.tactic.name)
            tactic_ids.append(entry.tactic.id)

            for technique in entry.technique or []:
                technique_names.add(technique.name)
                technique_ids.add(technique.id)

                for subtechnique in technique.subtechnique or []:
                    sub_technique_ids.add(subtechnique.id)
                    sub_technique_names.add(subtechnique.name)

        return FlatThreatMapping(
            tactic_names=sorted(tactic_names),
            tactic_ids=sorted(tactic_ids),
            technique_names=sorted(technique_names),
            technique_ids=sorted(technique_ids),
            sub_technique_names=sorted(sub_technique_names),
            sub_technique_ids=sorted(sub_technique_ids),
        )


@dataclass(frozen=True, kw_only=True)
class RiskScoreMapping(MarshmallowDataclassMixin):
    field: str
    operator: definitions.Operator | None = None
    value: str | None = None


@dataclass(frozen=True, kw_only=True)
class SeverityMapping(MarshmallowDataclassMixin):
    field: str
    operator: definitions.Operator | None = None
    value: str | None = None
    severity: str | None = None


@dataclass(frozen=True)
class FlatThreatMapping(MarshmallowDataclassMixin):
    tactic_names: list[str]
    tactic_ids: list[str]
    technique_names: list[str]
    technique_ids: list[str]
    sub_technique_names: list[str]
    sub_technique_ids: list[str]


@dataclass(frozen=True)
class AlertSuppressionDuration:
    """Mapping to alert suppression duration."""

    unit: definitions.TimeUnits
    value: definitions.AlertSuppressionValue


@dataclass(frozen=True, kw_only=True)
class AlertSuppressionMapping(MarshmallowDataclassMixin, StackCompatMixin):
    """Mapping to alert suppression."""

    group_by: definitions.AlertSuppressionGroupBy
    duration: AlertSuppressionDuration | None = None
    missing_fields_strategy: definitions.AlertSuppressionMissing


@dataclass(frozen=True)
class ThresholdAlertSuppression:
    """Mapping to alert suppression."""

    duration: AlertSuppressionDuration


@dataclass(frozen=True)
class FilterStateStore:
    store: definitions.StoreType


@dataclass(frozen=True, kw_only=True)
class FilterMeta:
    alias: str | None = None
    disabled: bool | None = None
    negate: bool | None = None
    controlledBy: str | None  # identify who owns the filter
    group: str | None  # allows grouping of filters
    index: str | None = None
    isMultiIndex: bool | None = None
    type: str | None = None
    key: str | None = None
    params: str | None = None  # Expand to FilterMetaParams when needed
    value: str | None = None


@dataclass(frozen=True)
class WildcardQuery:
    case_insensitive: bool
    value: str


@dataclass(frozen=True, kw_only=True)
class Query:
    wildcard: dict[str, WildcardQuery] | None = None


@dataclass(frozen=True, kw_only=True)
class Filter:
    """Kibana Filter for Base Rule Data."""

    # Currently unused in BaseRuleData. Revisit to extend or remove.
    # https://github.com/elastic/detection-rules/issues/3773
    meta: FilterMeta
    state: FilterStateStore | None = field(metadata={"data_key": "$state"})
    query: Query | dict[str, Any] | None = None


@dataclass(frozen=True, kw_only=True)
class BaseRuleData(MarshmallowDataclassMixin, StackCompatMixin):
    """Base rule data."""

    @dataclass
    class InvestigationFields:
        field_names: list[definitions.NonEmptyStr]

    @dataclass
    class RequiredFields:
        name: definitions.NonEmptyStr
        type: definitions.NonEmptyStr
        ecs: bool

    @dataclass
    class RelatedIntegrations:
        package: definitions.NonEmptyStr
        version: definitions.NonEmptyStr
        integration: definitions.NonEmptyStr | None = None

    name: definitions.RuleName

    author: list[str]
    description: str
    from_: str | None = field(metadata={"data_key": "from"})
    investigation_fields: InvestigationFields | None = field(metadata={"metadata": {"min_compat": "8.11"}})
    related_integrations: list[RelatedIntegrations] | None = field(metadata={"metadata": {"min_compat": "8.3"}})
    required_fields: list[RequiredFields] | None = field(metadata={"metadata": {"min_compat": "8.3"}})
    revision: int | None = field(metadata={"metadata": {"min_compat": "8.8"}})
    setup: definitions.Markdown | None = field(metadata={"metadata": {"min_compat": "8.3"}})

    risk_score: definitions.RiskScore
    rule_id: definitions.UUIDString
    severity: definitions.Severity
    type: definitions.RuleType

    actions: list[dict[str, Any]] | None = None
    building_block_type: definitions.BuildingBlockType | None = None
    enabled: bool | None = None
    exceptions_list: list[dict[str, str]] | None = None
    false_positives: list[str] | None = None
    filters: list[dict[str, Any]] | None = None
    interval: definitions.Interval | None = None
    license: str | None = None
    max_signals: definitions.MaxSignals | None = None
    meta: dict[str, Any] | None = None
    note: definitions.Markdown | None = None
    references: list[str] | None = None
    risk_score_mapping: list[RiskScoreMapping] | None = None
    rule_name_override: str | None = None
    severity_mapping: list[SeverityMapping] | None = None
    tags: list[str] | None = None
    threat: list[ThreatMapping] | None = None
    throttle: str | None = None
    timeline_id: definitions.TimelineTemplateId | None = None
    timeline_title: definitions.TimelineTemplateTitle | None = None
    timestamp_override: str | None = None
    to: str | None = None
    version: definitions.PositiveInteger | None = None

    @classmethod
    def save_schema(cls) -> None:
        """Save the schema as a jsonschema."""
        fields: tuple[dataclasses.Field[Any], ...] = dataclasses.fields(cls)
        type_field = next(f for f in fields if f.name == "type")
        rule_type = typing.get_args(type_field.type)[0] if cls != BaseRuleData else "base"
        schema = cls.jsonschema()
        version_dir = SCHEMA_DIR / "master"
        version_dir.mkdir(exist_ok=True, parents=True)

        # expand out the jsonschema definitions
        with (version_dir / f"master.{rule_type}.json").open("w") as f:
            json.dump(schema, f, indent=2, sort_keys=True)

    def validate_query(self, _: RuleMeta) -> None:
        pass

    @cached_property
    def get_restricted_fields(self) -> dict[str, tuple[Version | None, Version | None]] | None:
        """Get stack version restricted fields."""
        fields: list[dataclasses.Field[Any]] = list(dataclasses.fields(self))
        return get_restricted_fields(fields)

    @cached_property
    def data_validator(self) -> "DataValidator | None":
        return DataValidator(is_elastic_rule=self.is_elastic_rule, **self.to_dict())

    @cached_property
    def notify(self) -> bool:
        return os.environ.get("DR_NOTIFY_INTEGRATION_UPDATE_AVAILABLE") is not None

    @cached_property
    def parsed_note(self) -> MarkoDocument | None:
        dv = self.data_validator
        if dv:
            return dv.parsed_note
        return None

    @property
    def is_elastic_rule(self) -> bool:
        return "elastic" in [a.lower() for a in self.author]

    def get_build_fields(self) -> dict[str, tuple[Version, None]]:
        """Get a list of build-time fields along with the stack versions which they will build within."""
        rule_fields = {f.name: f for f in dataclasses.fields(self)}
        return {fld: val for fld, val in BUILD_FIELD_VERSIONS.items() if fld in rule_fields}

    @classmethod
    def process_transforms(cls, transform: RuleTransform, obj: dict[str, Any]) -> dict[str, Any]:
        """Process transforms from toml [transform] called in TOMLRuleContents.to_dict."""
        # only create functions that CAREFULLY mutate the obj dict

        # Format the note field with osquery and investigate plugin strings
        note = obj.get("note")
        if not note:
            return obj

        rendered = transform.render_investigate_osquery_to_string()
        rendered_patterns: dict[str, Any] = {}
        for plugin, entries in rendered.items():
            rendered_patterns.update(**{f"{plugin}_{i}": e for i, e in enumerate(entries)})  # type: ignore[reportUnknownMemberType]

        note_template = PatchedTemplate(note)
        rendered_note = note_template.safe_substitute(**rendered_patterns)
        obj["note"] = rendered_note

        return obj

    @validates_schema
    def validates_data(self, data: dict[str, Any], **_: Any) -> None:
        """Validate fields and data for marshmallow schemas."""

        # Validate version and revision fields not supplied.
        disallowed_fields = [field for field in ["version", "revision"] if data.get(field) is not None]
        if not disallowed_fields:
            return

        # If version and revision fields are supplied, and using locked versions raise an error.
        if BYPASS_VERSION_LOCK is not True:
            error_message = " and ".join(disallowed_fields)
            msg = (
                f"Configuration error: Rule {data['name']} - {data['rule_id']} "
                f"should not contain rules with `{error_message}` set."
            )
            raise ValidationError(msg)


class DataValidator:
    """Additional validation beyond base marshmallow schema validation."""

    def __init__(  # noqa: PLR0913
        self,
        name: definitions.RuleName,
        is_elastic_rule: bool,
        note: definitions.Markdown | None = None,
        interval: definitions.Interval | None = None,
        building_block_type: definitions.BuildingBlockType | None = None,
        setup: str | None = None,
        **extras: Any,
    ) -> None:
        # only define fields needing additional validation
        self.name = name
        self.is_elastic_rule = is_elastic_rule
        self.note = note
        # Need to use extras because from is a reserved word in python
        self.from_ = extras.get("from")
        self.interval = interval
        self.building_block_type = building_block_type
        self.setup = setup
        self._setup_in_note = False

    @cached_property
    def parsed_note(self) -> MarkoDocument | None:
        if self.note:
            return gfm.parse(self.note)
        return None

    @property
    def setup_in_note(self) -> bool:
        return self._setup_in_note

    @setup_in_note.setter
    def setup_in_note(self, value: bool) -> None:
        self._setup_in_note = value

    @cached_property
    def skip_validate_note(self) -> bool:
        return os.environ.get("DR_BYPASS_NOTE_VALIDATION_AND_PARSE") is not None

    @cached_property
    def skip_validate_bbr(self) -> bool:
        return os.environ.get("DR_BYPASS_BBR_LOOKBACK_VALIDATION") is not None

    def validate_bbr(self, bypass: bool = False) -> None:
        """Validate building block type and rule type."""

        if self.skip_validate_bbr or bypass:
            return

        def validate_lookback(str_time: str) -> bool:
            """Validate that the time is at least now-119m and at least 60m respectively."""
            try:
                if "now-" in str_time:
                    str_time = str_time[4:]
                    time = convert_time_span(str_time)
                    # if from time is less than 119m as milliseconds
                    if time < 119 * 60 * 1000:
                        return False
                else:
                    return False
            except Exception as e:
                raise ValidationError(f"Invalid time format: {e}") from e
            return True

        def validate_interval(str_time: str) -> bool:
            """Validate that the time is at least now-119m and at least 60m respectively."""
            try:
                time = convert_time_span(str_time)
                # if interval time is less than 60m as milliseconds
                if time < 60 * 60 * 1000:
                    return False
            except Exception as e:
                raise ValidationError(f"Invalid time format: {e}") from e
            return True

        bypass_instructions = "To bypass, use the environment variable `DR_BYPASS_BBR_LOOKBACK_VALIDATION`"
        if self.building_block_type:
            if not self.from_ or not self.interval:
                raise ValidationError(
                    f"{self.name} is invalid."
                    "BBR require `from` and `interval` to be defined. "
                    "Please set or bypass." + bypass_instructions
                )
            if not validate_lookback(self.from_) or not validate_interval(self.interval):
                raise ValidationError(
                    f"{self.name} is invalid."
                    "Default BBR require `from` and `interval` to be at least now-119m and at least 60m respectively "
                    "(using the now-Xm and Xm format where x is in minutes). "
                    "Please update values or bypass. " + bypass_instructions
                )

    def validate_note(self) -> None:
        if self.skip_validate_note or not self.note:
            return

        if not self.parsed_note:
            return

        try:
            for child in self.parsed_note.children:
                if child.get_type() == "Heading":
                    header = gfm.renderer.render_children(child)

                    if header.lower() == "setup":
                        # check that the Setup header is correctly formatted at level 2
                        if child.level != 2:  # type: ignore[reportAttributeAccessIssue]  # noqa: PLR2004
                            raise ValidationError(f"Setup section with wrong header level: {child.level}")  # type: ignore[reportAttributeAccessIssue]  # noqa: TRY301

                        # check that the Setup header is capitalized
                        if child.level == 2 and header != "Setup":  # type: ignore[reportAttributeAccessIssue]  # noqa: PLR2004
                            raise ValidationError(f"Setup header has improper casing: {header}")  # noqa: TRY301

                        self.setup_in_note = True

                    # check that the header Config does not exist in the Setup section
                    elif child.level == 2 and "config" in header.lower():  # type: ignore[reportAttributeAccessIssue]  # noqa: PLR2004
                        raise ValidationError(f"Setup header contains Config: {header}")  # noqa: TRY301

        except Exception as e:
            raise ValidationError(
                f"Invalid markdown in rule `{self.name}`: {e}. To bypass validation on the `note`"
                f"field, use the environment variable `DR_BYPASS_NOTE_VALIDATION_AND_PARSE`"
            ) from e

        # raise if setup header is in note and in setup
        if self.setup_in_note and (self.setup and self.setup != "None"):
            raise ValidationError("Setup header found in both note and setup fields.")


@dataclass
class QueryValidator:
    query: str

    @property
    def ast(self) -> Any:
        raise NotImplementedError

    @property
    def unique_fields(self) -> Any:
        raise NotImplementedError

    def validate(self, _: "QueryRuleData", __: RuleMeta) -> None:
        raise NotImplementedError

    @cached
    def get_required_fields(self, index: str) -> list[dict[str, Any]]:
        """Retrieves fields needed for the query along with type information from the schema."""

        current_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
        ecs_version = get_stack_schemas()[str(current_version)]["ecs"]
        beats_version = get_stack_schemas()[str(current_version)]["beats"]
        endgame_version = get_stack_schemas()[str(current_version)]["endgame"]
        ecs_schema = ecs.get_schema(ecs_version)

        _, beat_schema, schema = self.get_beats_schema(index or [], beats_version, ecs_version)
        endgame_schema = self.get_endgame_schema(index or [], endgame_version)

        # construct integration schemas
        packages_manifest = load_integrations_manifests()
        integrations_schemas = load_integrations_schemas()
        datasets: set[str] = set()
        if self.ast:
            datasets, _ = beats.get_datasets_and_modules(self.ast)
        package_integrations = parse_datasets(list(datasets), packages_manifest)
        int_schema: dict[str, Any] = {}
        data = {"notify": False}

        for pk_int in package_integrations:
            package = pk_int["package"]
            integration = pk_int["integration"]
            schema, _ = get_integration_schema_fields(
                integrations_schemas, package, integration, current_version, packages_manifest, {}, data
            )
            int_schema.update(schema)

        required: list[dict[str, Any]] = []
        unique_fields: list[str] = self.unique_fields or []

        for fld in unique_fields:
            field_type = ecs_schema.get(fld, {}).get("type")
            is_ecs = field_type is not None

            if not is_ecs:
                if int_schema:
                    field_type = int_schema.get(fld)
                elif beat_schema:
                    field_type = beat_schema.get(fld, {}).get("type")
                elif endgame_schema:
                    field_type = endgame_schema.endgame_schema.get(fld, None)

            if not field_type and isinstance(self, ESQLValidator):
                field_type = self.get_unique_field_type(fld)

            required.append({"name": fld, "type": field_type or "unknown", "ecs": is_ecs})

        return sorted(required, key=lambda f: f["name"])

    @cached
    def get_beats_schema(
        self, indices: list[str], beats_version: str, ecs_version: str
    ) -> tuple[list[str], dict[str, Any] | None, dict[str, Any]]:
        """Get an assembled beats schema."""
        beat_types = beats.parse_beats_from_index(indices)
        beat_schema = beats.get_schema_from_kql(self.ast, beat_types, version=beats_version) if beat_types else None
        schema = ecs.get_kql_schema(version=ecs_version, indexes=indices, beat_schema=beat_schema)
        return beat_types, beat_schema, schema

    @cached
    def get_endgame_schema(self, indices: list[str], endgame_version: str) -> endgame.EndgameSchema | None:
        """Get an assembled flat endgame schema."""
        # Only include endgame when explicitly requested by TOML via indices
        if not indices or "endgame-*" not in indices:
            return None

        endgame_schema = endgame.read_endgame_schema(endgame_version=endgame_version)
        return endgame.EndgameSchema(endgame_schema)


@dataclass(frozen=True, kw_only=True)
class QueryRuleData(BaseRuleData):
    """Specific fields for query event types."""

    type: Literal["query"]
    query: str
    language: definitions.FilterLanguages
    alert_suppression: AlertSuppressionMapping | None = field(metadata={"metadata": {"min_compat": "8.8"}})

    index: list[str] | None = None
    data_view_id: str | None = None

    @cached_property
    def index_or_dataview(self) -> list[str]:
        """Return the index or dataview depending on which is set. If neither returns empty list."""
        if self.index is not None:
            return self.index
        if self.data_view_id is not None:
            return [self.data_view_id]
        return []

    @cached_property
    def validator(self) -> QueryValidator | None:
        if self.language == "kuery":
            return KQLValidator(self.query)
        if self.language == "eql":
            return EQLValidator(self.query)
        if self.language == "esql":
            return ESQLValidator(self.query)
        return None

    def validate_query(self, meta: RuleMeta) -> None:  # type: ignore[reportIncompatibleMethodOverride]
        validator = self.validator
        if validator:
            validator.validate(self, meta)

    @cached_property
    def ast(self) -> Any:
        validator = self.validator
        if validator is not None:
            return validator.ast
        return None

    @cached_property
    def unique_fields(self) -> None:
        validator = self.validator
        if validator is not None:
            return validator.unique_fields
        return None

    @cached
    def get_required_fields(self, index: str) -> list[dict[str, Any]] | None:
        validator = self.validator
        if validator is not None:
            return validator.get_required_fields(index or [])
        return None

    @validates_schema
    def validates_index_and_data_view_id(self, data: dict[str, Any], **_: Any) -> None:
        """Validate that either index or data_view_id is set, but not both."""
        if data.get("index") and data.get("data_view_id"):
            raise ValidationError("Only one of index or data_view_id should be set.")


@dataclass(frozen=True, kw_only=True)
class MachineLearningRuleData(BaseRuleData):
    type: Literal["machine_learning"]

    anomaly_threshold: int
    machine_learning_job_id: str | list[str]
    alert_suppression: AlertSuppressionMapping | None = field(metadata={"metadata": {"min_compat": "8.15"}})


@dataclass(frozen=True, kw_only=True)
class ThresholdQueryRuleData(QueryRuleData):
    """Specific fields for query event types."""

    @dataclass(frozen=True, kw_only=True)
    class ThresholdMapping(MarshmallowDataclassMixin):
        @dataclass(frozen=True)
        class ThresholdCardinality:
            field: str
            value: definitions.ThresholdValue

        field: definitions.CardinalityFields
        value: definitions.ThresholdValue
        cardinality: list[ThresholdCardinality] | None = None

    type: Literal["threshold"]  # type: ignore[reportIncompatibleVariableOverride]
    threshold: ThresholdMapping
    alert_suppression: ThresholdAlertSuppression | None = field(metadata={"metadata": {"min_compat": "8.12"}})  # type: ignore[reportIncompatibleVariableOverride]

    def validate(self, meta: RuleMeta) -> None:
        """Validate threshold fields count based on stack version."""
        current_min_stack = load_current_package_version()
        min_stack_raw = meta.min_stack_version or current_min_stack
        min_stack = Version.parse(min_stack_raw, optional_minor_and_patch=True)
        cutoff = Version.parse("9.2.0")

        default_cap_lt_9_2 = 3
        default_cap_ge_9_2 = 5
        is_ge_9_2 = min_stack >= cutoff
        max_fields_allowed = default_cap_ge_9_2 if is_ge_9_2 else default_cap_lt_9_2

        fields = self.threshold.field or []
        if len(fields) > max_fields_allowed:
            # Tailored hint based on stack cap in effect
            if is_ge_9_2:
                hint = f" Reduce to {max_fields_allowed} or fewer fields."
            else:
                hint = (
                    f" Reduce to {max_fields_allowed} or fewer fields, or set "
                    "metadata.min_stack_version to 9.2.0+ "
                    f"to allow up to {default_cap_ge_9_2}."
                )

            raise ValidationError(
                f"threshold field supports at most {max_fields_allowed} field(s) for min_stack_version "
                f"{min_stack_raw or 'unspecified (<9.2 assumed)'}. "
                f"Received {len(fields)} group_by fields." + hint
            )


@dataclass(frozen=True, kw_only=True)
class NewTermsRuleData(QueryRuleData):
    """Specific fields for new terms field rule."""

    @dataclass(frozen=True)
    class NewTermsMapping(MarshmallowDataclassMixin):
        @dataclass(frozen=True)
        class HistoryWindowStart:
            field: definitions.NonEmptyStr
            value: definitions.NonEmptyStr

        field: definitions.NonEmptyStr
        value: definitions.NewTermsFields
        history_window_start: list[HistoryWindowStart]

    type: Literal["new_terms"]  # type: ignore[reportIncompatibleVariableOverride]
    new_terms: NewTermsMapping
    alert_suppression: AlertSuppressionMapping | None = field(metadata={"metadata": {"min_compat": "8.14"}})

    @pre_load
    def preload_data(self, data: dict[str, Any], **_: Any) -> dict[str, Any]:
        """Preloads and formats the data to match the required schema."""
        if "new_terms_fields" in data and "history_window_start" in data:
            new_terms_mapping = {
                "field": "new_terms_fields",
                "value": data["new_terms_fields"],
                "history_window_start": [{"field": "history_window_start", "value": data["history_window_start"]}],
            }
            data["new_terms"] = new_terms_mapping

            # cleanup original fields after building into our toml format
            data.pop("new_terms_fields")
            data.pop("history_window_start")
        return data

    def transform(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Transforms new terms data to API format for Kibana."""
        obj[obj["new_terms"].get("field")] = obj["new_terms"].get("value")
        obj["history_window_start"] = obj["new_terms"]["history_window_start"][0].get("value")
        del obj["new_terms"]
        return obj


@dataclass(frozen=True, kw_only=True)
class EQLRuleData(QueryRuleData):
    """EQL rules are a special case of query rules."""

    type: Literal["eql"]  # type: ignore[reportIncompatibleVariableOverride]
    language: Literal["eql"]
    timestamp_field: str | None = field(metadata={"metadata": {"min_compat": "8.0"}})
    event_category_override: str | None = field(metadata={"metadata": {"min_compat": "8.0"}})
    tiebreaker_field: str | None = field(metadata={"metadata": {"min_compat": "8.0"}})
    alert_suppression: AlertSuppressionMapping | None = field(metadata={"metadata": {"min_compat": "8.14"}})

    def convert_relative_delta(self, lookback: str) -> int:
        now = len("now")
        min_length = now + len("+5m")

        if lookback.startswith("now") and len(lookback) >= min_length:
            lookback = lookback[len("now") :]
            sign = lookback[0]  # + or -
            span = lookback[1:]
            amount = convert_time_span(span)
            return amount * (-1 if sign == "-" else 1)
        return convert_time_span(lookback)

    @cached_property
    def is_sample(self) -> bool:
        """Checks if the current rule is a sample-based rule."""
        return eql.utils.get_query_type(self.ast) == "sample"  # type: ignore[reportUnknownMemberType]

    @cached_property
    def is_sequence(self) -> bool:
        """Checks if the current rule is a sequence-based rule."""
        return eql.utils.get_query_type(self.ast) == "sequence"  # type: ignore[reportUnknownMemberType]

    @cached_property
    def max_span(self) -> int | None:
        """Maxspan value for sequence rules if defined."""
        if not self.ast:
            raise ValueError("No AST found")
        if self.is_sequence and hasattr(self.ast.first, "max_span"):
            return self.ast.first.max_span.as_milliseconds() if self.ast.first.max_span else None
        return None

    @cached_property
    def look_back(self) -> int | Literal["unknown"] | None:
        """Lookback value of a rule."""
        # https://www.elastic.co/guide/en/elasticsearch/reference/current/common-options.html#date-math
        to = self.convert_relative_delta(self.to) if self.to else 0
        from_ = self.convert_relative_delta(self.from_ or "now-6m")

        if not (to or from_):
            return "unknown"
        return to - from_

    @cached_property
    def interval_ratio(self) -> float | None:
        """Ratio of interval time window / max_span time window."""
        if self.max_span:
            interval = convert_time_span(self.interval or "5m")
            return interval / self.max_span
        return None


@dataclass(frozen=True, kw_only=True)
class ESQLRuleData(QueryRuleData):
    """ESQL rules are a special case of query rules."""

    type: Literal["esql"]  # type: ignore[reportIncompatibleVariableOverride]
    language: Literal["esql"]
    query: str
    alert_suppression: AlertSuppressionMapping | None = field(metadata={"metadata": {"min_compat": "8.15"}})

    @validates_schema
    def validates_esql_data(self, data: dict[str, Any], **_: Any) -> None:
        """Custom validation for query rule type and subclasses."""
        if data.get("index"):
            raise EsqlSemanticError("Index is not a valid field for ES|QL rule type.")

        # Convert the query string to lowercase to handle case insensitivity
        query_lower = data["query"].lower()

        # Combine both patterns using an OR operator and compile the regex.
        # The first part matches the metadata fields in the from clause by allowing one or
        # multiple indices and any order of the metadata fields
        # The second part matches the stats command with the by clause
        combined_pattern = re.compile(
            r"(from\s+(?:\S+\s*,\s*)*\S+\s+metadata\s+"
            r"(?:_id|_version|_index)(?:,\s*(?:_id|_version|_index)){2})"
            r"|(\bstats\b.*?\bby\b)",
            re.DOTALL,
        )

        # Ensure that non-aggregate queries have metadata
        if not combined_pattern.search(query_lower):
            raise EsqlSemanticError(
                f"Rule: {data['name']} contains a non-aggregate query without"
                f" metadata fields '_id', '_version', and '_index' ->"
                f" Add 'metadata _id, _version, _index' to the from command or add an aggregate function."
            )

        # Enforce KEEP command for ESQL rules
        # Match | followed by optional whitespace/newlines and then 'keep'
        keep_pattern = re.compile(r"\|\s*keep\b", re.IGNORECASE | re.DOTALL)
        if not keep_pattern.search(query_lower):
            raise EsqlSemanticError(
                f"Rule: {data['name']} does not contain a 'keep' command -> Add a 'keep' command to the query."
            )


@dataclass(frozen=True, kw_only=True)
class ThreatMatchRuleData(QueryRuleData):
    """Specific fields for indicator (threat) match rule."""

    @dataclass(frozen=True)
    class Entries:
        @dataclass(frozen=True)
        class ThreatMapEntry(StackCompatMixin):
            field: definitions.NonEmptyStr
            type: Literal["mapping"]
            value: definitions.NonEmptyStr
            # Use dataclasses.field to avoid shadowing by attribute name "field"
            negate: bool | None = dataclasses.field(  # type: ignore[reportIncompatibleVariableOverride]
                metadata={"metadata": {"min_compat": "9.2"}}
            )

        entries: list[ThreatMapEntry]

    type: Literal["threat_match"]  # type: ignore[reportIncompatibleVariableOverride]

    concurrent_searches: definitions.PositiveInteger | None = None
    items_per_search: definitions.PositiveInteger | None = None

    threat_mapping: list[Entries]
    threat_filters: list[dict[str, Any]] | None = None
    threat_query: str | None = None
    threat_language: definitions.FilterLanguages | None = None
    threat_index: list[str]
    threat_indicator_path: str | None = None
    alert_suppression: AlertSuppressionMapping | None = field(metadata={"metadata": {"min_compat": "8.13"}})

    def validate_query(self, meta: RuleMeta) -> None:
        super().validate_query(meta)

        if self.threat_query:
            if not self.threat_language:
                raise ValidationError("`threat_language` required when a `threat_query` is defined")

            if self.threat_language == "kuery":
                threat_query_validator = KQLValidator(self.threat_query)
            elif self.threat_language == "eql":
                threat_query_validator = EQLValidator(self.threat_query)
            else:
                return

            threat_query_validator.validate(self, meta)

    def validate(self, meta: RuleMeta) -> None:  # noqa: ARG002
        """Validate negate usage and group semantics for threat mapping."""

        for idx, group in enumerate(self.threat_mapping or []):
            entries = group.entries or []

            # Enforce: DOES NOT MATCH entries are allowed only if there is at least
            # one MATCH (non-negated) entry in the same group
            has_negate = any(bool(getattr(e, "negate", False)) for e in entries)
            has_match = any(not bool(getattr(e, "negate", False)) for e in entries)
            if has_negate and not has_match:
                msg = (
                    f"threat_mapping group {idx}: DOES NOT MATCH entries require at least one MATCH "
                    "(non-negated) entry in the same group."
                )
                raise ValidationError(msg)

            # Track negate presence per (source.field, indicator.field) pair to detect
            # conflicts where both MATCH and DOES NOT MATCH are defined for the same pair
            pair_to_negates: dict[tuple[str, str], set[bool]] = {}
            for e in entries:
                is_neg = bool(getattr(e, "negate", False))
                pair_to_negates.setdefault((e.field, e.value), set()).add(is_neg)

            for (src_field, ind_field), flags in pair_to_negates.items():
                if True in flags and False in flags:
                    msg = (
                        f"threat_mapping group {idx}: cannot define both MATCH and DOES NOT MATCH for the same "
                        f"source and indicator fields: '{src_field}' <-> '{ind_field}'."
                    )
                    raise ValidationError(msg)


# All of the possible rule types
# Sort inverse of any inheritance - see comment in TOMLRuleContents.to_dict
# ThresholdQueryRuleData needs to be first in this union to handle cases where there is ambiguity between
# ThresholdAlertSuppression and AlertSuppressionMapping. Since AlertSuppressionMapping has duration as an
# optional field, ThresholdAlertSuppression objects can be mistakenly loaded as an AlertSuppressionMapping
# object with group_by and missing_fields_strategy as missing parameters, resulting in an error.
# Checking the type against ThresholdQueryRuleData first in the union prevent this from occurring.
# Please also keep issue 1141 in mind when handling union schemas.

AnyRuleData = (
    ThresholdQueryRuleData
    | EQLRuleData
    | ESQLRuleData
    | ThreatMatchRuleData
    | MachineLearningRuleData
    | QueryRuleData
    | NewTermsRuleData
)


class BaseRuleContents(ABC):
    """Base contents object for shared methods between active and deprecated rules."""

    @property
    @abstractmethod
    def id(self) -> str:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def version_lock(self) -> "VersionLock":
        pass

    @property
    @abstractmethod
    def type(self) -> str:
        pass

    def lock_info(self, bump: bool = True) -> dict[str, Any]:
        version = self.autobumped_version if bump else (self.saved_version or 1)
        return {"rule_name": self.name, "sha256": self.get_hash(), "version": version, "type": self.type}

    @property
    def is_dirty(self) -> bool:
        """Determine if the rule has changed since its version was locked."""
        min_stack = Version.parse(self.get_supported_version(), optional_minor_and_patch=True)
        existing_sha256 = self.version_lock.get_locked_hash(self.id, f"{min_stack.major}.{min_stack.minor}")

        if not existing_sha256:
            return False

        rule_hash = self.get_hash()
        rule_hash_with_integrations = self.get_hash(include_integrations=True)

        # Checking against current and previous version of the hash to avoid mass version bump
        return existing_sha256 not in (rule_hash, rule_hash_with_integrations)

    @property
    def lock_entry(self) -> dict[str, Any] | None:
        lock_entry = self.version_lock.version_lock.data.get(self.id)
        if lock_entry:
            return lock_entry.to_dict()
        return None

    @property
    def has_forked(self) -> bool:
        """Determine if the rule has forked at any point (has a previous entry)."""
        lock_entry = self.lock_entry
        if lock_entry:
            return "previous" in lock_entry
        return False

    @property
    def is_in_forked_version(self) -> bool:
        """Determine if the rule is in a forked version."""
        if not self.has_forked:
            return False
        if not self.lock_entry:
            raise ValueError("No lock entry found")
        locked_min_stack = Version.parse(self.lock_entry["min_stack_version"], optional_minor_and_patch=True)
        current_package_ver = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
        return current_package_ver < locked_min_stack

    def get_version_space(self) -> int | None:
        """Retrieve the number of version spaces available (None for unbound)."""
        if self.is_in_forked_version:
            if not self.lock_entry:
                raise ValueError("No lock entry found")

            current_entry = self.lock_entry["previous"][self.metadata.min_stack_version]  # type: ignore[reportAttributeAccessIssue]
            current_version = current_entry["version"]
            max_allowable_version = current_entry["max_allowable_version"]

            return max_allowable_version - current_version - 1
        return None

    @property
    def saved_version(self) -> int | None:
        """Retrieve the version from the version.lock or from the file if version locking is bypassed."""

        toml_version = self.data.get("version")  # type: ignore[reportAttributeAccessIssue]

        if BYPASS_VERSION_LOCK:
            return toml_version  # type: ignore[reportUnknownVariableType]

        if toml_version:
            print(
                f"WARNING: Rule {self.name} - {self.id} has a version set in the rule TOML."
                " This `version` will be ignored and defaulted to the version.lock.json file."
                " Set `bypass_version_lock` to `True` in the rules config to use the TOML version."
            )

        return self.version_lock.get_locked_version(self.id, self.get_supported_version())

    @property
    def autobumped_version(self) -> int | None:
        """Retrieve the current version of the rule, accounting for automatic increments."""
        version = self.saved_version

        if BYPASS_VERSION_LOCK:
            raise NotImplementedError("This method is not implemented when version locking is not in use.")

        # Default to version 1 if no version is set yet
        if version is None:
            return 1

        # Auto-increment version if the rule is 'dirty' and not bypassing version lock
        return version + 1 if self.is_dirty else version

    def get_synthetic_version(self, use_default: bool) -> int | None:
        """
        Get the latest actual representation of a rule's version, where changes are accounted for automatically when
        version locking is used, otherwise, return the version defined in the rule toml if present else optionally
        default to 1.
        """
        return self.autobumped_version or self.saved_version or (1 if use_default else None)

    @classmethod
    def convert_supported_version(cls, stack_version: str | None) -> Version:
        """Convert an optional stack version to the minimum for the lock in the form major.minor."""
        min_version = get_min_supported_stack_version()
        if stack_version is None:
            return min_version
        return max(Version.parse(stack_version, optional_minor_and_patch=True), min_version)

    def get_supported_version(self) -> str:
        """Get the lowest stack version for the rule that is currently supported in the form major.minor."""
        rule_min_stack = self.metadata.get("min_stack_version")  # type: ignore[reportAttributeAccessIssue]
        min_stack = self.convert_supported_version(rule_min_stack)  # type: ignore[reportUnknownArgumentType]
        return f"{min_stack.major}.{min_stack.minor}"

    def _post_dict_conversion(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Transform the converted API in place before sending to Kibana."""

        # cleanup the whitespace in the rule
        obj = nested_normalize(obj)

        # fill in threat.technique so it's never missing
        for threat_entry in obj.get("threat", []):
            threat_entry.setdefault("technique", [])

        return obj

    @abstractmethod
    def to_api_format(self, include_version: bool = True) -> dict[str, Any]:
        """Convert the rule to the API format."""

    def get_hashable_content(self, include_version: bool = False, include_integrations: bool = False) -> dict[str, Any]:
        """Returns the rule content to be used for calculating the hash value for the rule"""

        # get the API dict without the version by default, otherwise it'll always be dirty.
        hashable_dict = self.to_api_format(include_version=include_version)

        # drop related integrations if present
        if not include_integrations:
            hashable_dict.pop("related_integrations", None)

        return hashable_dict

    @cached
    def get_hash(self, include_version: bool = False, include_integrations: bool = False) -> str:
        """Returns a sha256 hash of the rule contents"""
        hashable_contents = self.get_hashable_content(
            include_version=include_version,
            include_integrations=include_integrations,
        )
        return utils.dict_hash(hashable_contents)


@dataclass(frozen=True)
class TOMLRuleContents(BaseRuleContents, MarshmallowDataclassMixin):
    """Rule object which maps directly to the TOML layout."""

    metadata: RuleMeta
    data: AnyRuleData = field(metadata={"data_key": "rule"})
    transform: RuleTransform | None = None

    @cached_property
    def version_lock(self) -> VersionLock:  # type: ignore[reportIncompatibleMethodOverride]
        if RULES_CONFIG.bypass_version_lock is True:
            err_msg = (
                "Cannot access the version lock when the versioning strategy is configured to bypass the"
                " version lock. Set `bypass_version_lock` to `false` in the rules config to use the version lock."
            )
            raise ValueError(err_msg)

        return getattr(self, "_version_lock", None) or loaded_version_lock

    def set_version_lock(self, value: VersionLock) -> None:
        if RULES_CONFIG.bypass_version_lock:
            raise ValueError(
                "Cannot set the version lock when the versioning strategy is configured to bypass the version lock."
                " Set `bypass_version_lock` to `false` in the rules config to use the version lock."
            )

        # circumvent frozen class
        self.__dict__["_version_lock"] = value

    @classmethod
    def all_rule_types(cls) -> set[str]:
        types: set[str] = set()
        for subclass in typing.get_args(AnyRuleData):
            field = next(field for field in dataclasses.fields(subclass) if field.name == "type")
            types.update(typing.get_args(field.type))

        return types

    @classmethod
    def get_data_subclass(cls, rule_type: str) -> type[BaseRuleData]:
        """Get the proper subclass depending on the rule type"""
        for subclass in typing.get_args(AnyRuleData):
            field = next(field for field in dataclasses.fields(subclass) if field.name == "type")
            if (rule_type,) == typing.get_args(field.type):
                return subclass

        raise ValueError(f"Unknown rule type {rule_type}")

    @property
    def id(self) -> definitions.UUIDString:
        return self.data.rule_id

    @property
    def name(self) -> str:
        return self.data.name

    @property
    def type(self) -> str:
        return self.data.type

    def _add_known_nulls(self, rule_dict: dict[str, Any]) -> dict[str, Any]:
        """Add known nulls to the rule."""
        # Note this is primarily as a stopgap until add support for Rule Actions
        for pair in definitions.KNOWN_NULL_ENTRIES:
            for compound_key, sub_key in pair.items():
                value = get_nested_value(rule_dict, compound_key)
                if isinstance(value, list):
                    items_to_update: list[dict[str, Any]] = [
                        item
                        for item in value  # type: ignore[reportUnknownVariableType]
                        if isinstance(item, dict) and get_nested_value(item, sub_key) is None
                    ]
                    for item in items_to_update:
                        set_nested_value(item, sub_key, None)
        return rule_dict

    def _post_dict_conversion(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Transform the converted API in place before sending to Kibana."""
        _ = super()._post_dict_conversion(obj)

        # build time fields
        self._convert_add_related_integrations(obj)
        self._convert_add_required_fields(obj)
        self._convert_add_setup(obj)

        # validate new fields against the schema
        rule_type = obj["type"]
        subclass = self.get_data_subclass(rule_type)
        subclass.from_dict(obj)

        # rule type transforms
        self.data.transform(obj) if hasattr(self.data, "transform") else False  # type: ignore[reportAttributeAccessIssue]

        return obj

    def _convert_add_related_integrations(self, obj: dict[str, Any]) -> None:
        """Add restricted field related_integrations to the obj."""
        field_name = "related_integrations"
        package_integrations = obj.get(field_name, [])

        if not package_integrations and self.metadata.integration:
            packages_manifest = load_integrations_manifests()
            current_stack_version = load_current_package_version()

            if self.check_restricted_field_version(field_name) and isinstance(
                self.data, QueryRuleData | MachineLearningRuleData
            ):  # type: ignore[reportUnnecessaryIsInstance]
                if (self.data.get("language") is not None and self.data.get("language") != "lucene") or self.data.get(
                    "type"
                ) == "machine_learning":
                    package_integrations = self.get_packaged_integrations(
                        self.data,  # type: ignore[reportArgumentType]
                        self.metadata,
                        packages_manifest,
                    )

                    if not package_integrations:
                        return

                    for package in package_integrations:
                        package["version"] = find_least_compatible_version(
                            package=package["package"],
                            integration=package["integration"],
                            current_stack_version=current_stack_version,
                            packages_manifest=packages_manifest,
                        )

                        # if integration is not a policy template remove
                        if package["version"]:
                            version_data = packages_manifest.get(package["package"], {}).get(
                                package["version"].strip("^"), {}
                            )
                            policy_templates = version_data.get("policy_templates", [])

                            if package["integration"] not in policy_templates:
                                del package["integration"]

                # remove duplicate entries
                package_integrations = list({json.dumps(d, sort_keys=True): d for d in package_integrations}.values())
                obj.setdefault("related_integrations", package_integrations)

    def _convert_add_required_fields(self, obj: dict[str, Any]) -> None:
        """Add restricted field required_fields to the obj, derived from the query AST."""
        if isinstance(self.data, QueryRuleData) and self.data.language != "lucene":
            index: list[str] = obj.get("index") or []
            required_fields = self.data.get_required_fields(index)
        else:
            required_fields = []

        field_name = "required_fields"
        if required_fields and self.check_restricted_field_version(field_name=field_name):
            obj.setdefault(field_name, required_fields)

    def _convert_add_setup(self, obj: dict[str, Any]) -> None:
        """Add restricted field setup to the obj."""
        rule_note = obj.get("note", "")
        field_name = "setup"
        field_value = obj.get(field_name)

        if not self.check_explicit_restricted_field_version(field_name):
            return

        data_validator = self.data.data_validator

        if not data_validator:
            raise ValueError("No data validator found")

        if not data_validator.skip_validate_note and data_validator.setup_in_note and not field_value:
            parsed_note = self.data.parsed_note

            if not parsed_note:
                raise ValueError("No parsed note found")

            # parse note tree
            for i, child in enumerate(parsed_note.children):
                if child.get_type() == "Heading" and "Setup" in gfm.render(child):  # type: ignore[reportArgumentType]
                    field_value = self._convert_get_setup_content(parsed_note.children[i + 1 :])

                    # clean up old note field
                    investigation_guide = rule_note.replace("## Setup\n\n", "")
                    investigation_guide = investigation_guide.replace(field_value, "").strip()
                    obj["note"] = investigation_guide
                    obj[field_name] = field_value
                    break

    @cached
    def _convert_get_setup_content(self, note_tree: list[Any]) -> str:
        """Get note paragraph starting from the setup header."""
        setup: list[str] = []
        for child in note_tree:
            if child.get_type() == "BlankLine" or child.get_type() == "LineBreak":
                setup.append("\n")
            elif child.get_type() == "CodeSpan":
                setup.append(f"`{gfm.renderer.render_raw_text(child)}`")  # type: ignore[reportUnknownMemberType]
            elif child.get_type() == "Paragraph":
                setup.append(self._convert_get_setup_content(child.children))
                setup.append("\n")
            elif child.get_type() == "FencedCode":
                setup.append(f"```\n{self._convert_get_setup_content(child.children)}\n```")
                setup.append("\n")
            elif child.get_type() == "RawText":
                setup.append(child.children)
            elif child.get_type() == "Heading" and child.level >= 2:  # noqa: PLR2004
                break
            else:
                setup.append(self._convert_get_setup_content(child.children))

        return "".join(setup).strip()

    def check_explicit_restricted_field_version(self, field_name: str) -> bool:
        """Explicitly check restricted fields against global min and max versions."""
        min_stack, max_stack = BUILD_FIELD_VERSIONS[field_name]
        if not min_stack or not max_stack:
            return True
        return self.compare_field_versions(min_stack, max_stack)

    def check_restricted_field_version(self, field_name: str) -> bool:
        """Check restricted fields against schema min and max versions."""
        if not self.data.get_restricted_fields:
            raise ValueError("No restricted fields found")
        min_stack, max_stack = self.data.get_restricted_fields[field_name]
        if not min_stack or not max_stack:
            return True
        return self.compare_field_versions(min_stack, max_stack)

    @staticmethod
    def compare_field_versions(min_stack: Version, max_stack: Version) -> bool:
        """Check current rule version is within min and max stack versions."""
        current_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
        max_stack = max_stack or current_version
        return min_stack <= current_version >= max_stack

    @classmethod
    def get_packaged_integrations(
        cls,
        data: QueryRuleData,
        meta: RuleMeta,
        package_manifest: dict[str, Any],
    ) -> list[dict[str, Any]] | None:
        packaged_integrations: list[dict[str, Any]] = []
        datasets, _ = beats.get_datasets_and_modules(data.get("ast") or [])  # type: ignore[reportArgumentType]
        if isinstance(data, ESQLRuleData):
            dataset_objs = get_esql_query_event_dataset_integrations(data.query)
            datasets.update(str(obj) for obj in dataset_objs)
        # integration is None to remove duplicate references upstream in Kibana
        # chronologically, event.dataset, data_stream.dataset is checked for package:integration, then rule tags
        # if both exist, rule tags are only used if defined in definitions for non-dataset packages
        # of machine learning analytic packages

        rule_integrations: str | list[str] = meta.get("integration") or []
        if isinstance(rule_integrations, str):
            rule_integrations = [rule_integrations]
        for integration in rule_integrations:
            ineligible_integrations = [
                *definitions.NON_DATASET_PACKAGES,
                *map(str.lower, definitions.MACHINE_LEARNING_PACKAGES),
            ]
            if (
                integration in ineligible_integrations
                or isinstance(data, MachineLearningRuleData)
                or (isinstance(data, ESQLRuleData) and integration not in datasets)
            ):
                packaged_integrations.append({"package": integration, "integration": None})

        packaged_integrations.extend(parse_datasets(list(datasets), package_manifest))

        return packaged_integrations

    @validates_schema
    def post_conversion_validation(self, value: dict[str, Any], **_: Any) -> None:
        """Additional validations beyond base marshmallow schemas."""
        data: AnyRuleData = value["data"]
        metadata: RuleMeta = value["metadata"]

        if not data.data_validator:
            raise ValueError("No data validator found")

        test_config = RULES_CONFIG.test_config
        if not test_config.check_skip_by_rule_id(value["data"].rule_id):
            bypass = metadata.get("bypass_bbr_timing") or False
            data.validate_query(metadata)
            data.data_validator.validate_note()
            data.data_validator.validate_bbr(bypass)
            data.validate(metadata) if hasattr(data, "validate") else False  # type: ignore[reportUnknownMemberType]

    @staticmethod
    def validate_remote(remote_validator: "RemoteValidator", contents: "TOMLRuleContents") -> None:
        _ = remote_validator.validate_rule(contents)

    @classmethod
    def from_rule_resource(
        cls,
        rule: dict[str, Any],
        creation_date: str = TIME_NOW,
        updated_date: str = TIME_NOW,
        maturity: str = "development",
    ) -> "TOMLRuleContents":
        """Create a TOMLRuleContents from a kibana rule resource."""
        integrations = [r["package"] for r in rule["related_integrations"]]
        meta = {
            "creation_date": creation_date,
            "updated_date": updated_date,
            "maturity": maturity,
            "integration": integrations,
        }
        return cls.from_dict({"metadata": meta, "rule": rule, "transforms": None}, unknown=marshmallow.EXCLUDE)

    def to_dict(self, strip_none_values: bool = True) -> dict[str, Any]:
        # Load schemas directly from the data and metadata classes to avoid schema ambiguity which can
        # result from union fields which contain classes and related subclasses (AnyRuleData). See issue #1141
        metadata = self.metadata.to_dict(strip_none_values=strip_none_values)
        data = self.data.to_dict(strip_none_values=strip_none_values)
        if self.transform:
            data = self.data.process_transforms(self.transform, data)
        dict_obj = {"metadata": metadata, "rule": data}
        return nested_normalize(dict_obj)

    def flattened_dict(self) -> dict[str, Any]:
        flattened: dict[str, Any] = {}
        flattened.update(self.data.to_dict())
        flattened.update(self.metadata.to_dict())
        return flattened

    def to_api_format(
        self,
        include_version: bool = not BYPASS_VERSION_LOCK,
        include_metadata: bool = False,
    ) -> dict[str, Any]:
        """Convert the TOML rule to the API format."""

        rule_dict = self.to_dict()
        rule_dict = self._add_known_nulls(rule_dict)
        converted_data = rule_dict["rule"]
        converted = self._post_dict_conversion(converted_data)

        if include_metadata:
            converted["meta"] = rule_dict["metadata"]

        if include_version:
            converted["version"] = self.autobumped_version

        return converted

    def check_restricted_fields_compatibility(self) -> dict[str, dict[str, Any]]:
        """Check for compatibility between restricted fields and the min_stack_version of the rule."""
        default_min_stack = get_min_supported_stack_version()
        if self.metadata.min_stack_version is not None:
            min_stack = Version.parse(self.metadata.min_stack_version, optional_minor_and_patch=True)
        else:
            min_stack = default_min_stack
        restricted = self.data.get_restricted_fields

        if not restricted:
            raise ValueError("No restricted fields found")

        invalid: dict[str, dict[str, Any]] = {}
        for _field, values in restricted.items():
            if self.data.get(_field) is not None:
                min_allowed, _ = values

                if not min_allowed:
                    raise ValueError("Min allowed versino is None")

                if min_stack < min_allowed:
                    invalid[_field] = {"min_stack_version": min_stack, "min_allowed_version": min_allowed}

        return invalid


@dataclass
class TOMLRule:
    contents: TOMLRuleContents = field(hash=True)
    path: Path | None = None
    gh_pr: Any = field(hash=False, compare=False, default=None, repr=False)

    @property
    def id(self) -> definitions.UUIDString:
        return self.contents.id

    @property
    def name(self) -> str:
        return self.contents.data.name

    def get_asset(self) -> dict[str, Any]:
        """Generate the relevant fleet compatible asset."""
        return {"id": self.id, "attributes": self.contents.to_api_format(), "type": definitions.SAVED_OBJECT_TYPE}

    def get_base_rule_dir(self) -> Path | None:
        """Get the base rule directory for the rule."""
        if not self.path:
            raise ValueError("No path found")
        rule_path = self.path.resolve()
        for rules_dir in DEFAULT_PREBUILT_RULES_DIRS + DEFAULT_PREBUILT_BBR_DIRS:
            if rule_path.is_relative_to(rules_dir):
                return rule_path.relative_to(rules_dir)
        return None

    def save_toml(self, strip_none_values: bool = True) -> None:
        if self.path is None:
            raise ValueError(f"Can't save rule {self.name} (self.id) without a path")

        converted = {
            "metadata": self.contents.metadata.to_dict(),
            "rule": self.contents.data.to_dict(strip_none_values=strip_none_values),
        }
        if self.contents.transform:
            converted["transform"] = self.contents.transform.to_dict()

        if not self.path:
            raise ValueError("No path found")

        toml_write(converted, self.path.absolute())

    def save_json(self, path: Path, include_version: bool = True) -> None:
        path = path.with_suffix(".json")
        with path.absolute().open("w", newline="\n") as f:
            json.dump(self.contents.to_api_format(include_version=include_version), f, sort_keys=True, indent=2)
            _ = f.write("\n")


@dataclass(frozen=True)
class DeprecatedRuleContents(BaseRuleContents):
    metadata: dict[str, Any]
    data: dict[str, Any]
    transform: dict[str, Any] | None = None

    @cached_property
    def version_lock(self) -> VersionLock:  # type: ignore[reportIncompatibleMethodOverride]
        # VersionLock
        return getattr(self, "_version_lock", None) or loaded_version_lock

    def set_version_lock(self, value: VersionLock | None) -> None:
        if RULES_CONFIG.bypass_version_lock:
            raise ValueError(
                "Cannot set the version lock when the versioning strategy is configured to bypass the version lock."
                " Set `bypass_version_lock` to `false` in the rules config to use the version lock."
            )

        # circumvent frozen class
        self.__dict__["_version_lock"] = value

    @property
    def id(self) -> str | None:  # type: ignore[reportIncompatibleMethodOverride]
        return self.data.get("rule_id")

    @property
    def name(self) -> str | None:  # type: ignore[reportIncompatibleMethodOverride]
        return self.data.get("name")

    @property
    def type(self) -> str | None:  # type: ignore[reportIncompatibleMethodOverride]
        return self.data.get("type")

    @classmethod
    def from_dict(cls, obj: dict[str, Any]) -> "DeprecatedRuleContents":
        kwargs = {"metadata": obj["metadata"], "data": obj["rule"]}
        kwargs["transform"] = obj.get("transform")
        return cls(**kwargs)

    def to_api_format(self, include_version: bool = not BYPASS_VERSION_LOCK) -> dict[str, Any]:
        """Convert the TOML rule to the API format."""
        data = copy.deepcopy(self.data)
        if self.transform:
            transform = RuleTransform.from_dict(self.transform)
            _ = BaseRuleData.process_transforms(transform, data)

        converted = data
        if include_version:
            converted["version"] = self.autobumped_version

        return self._post_dict_conversion(converted)


class DeprecatedRule(dict[str, Any]):
    """Minimal dict object for deprecated rule."""

    def __init__(self, path: Path, contents: DeprecatedRuleContents, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.path = path
        self.contents = contents

    def __repr__(self) -> str:
        return f"{type(self).__name__}(contents={self.contents}, path={self.path})"

    @property
    def id(self) -> str | None:
        return self.contents.id

    @property
    def name(self) -> str | None:
        return self.contents.name


def downgrade_contents_from_rule(
    rule: TOMLRule,
    target_version: str,
    replace_id: bool = True,
    include_metadata: bool = False,
) -> dict[str, Any]:
    """Generate the downgraded contents from a rule."""
    rule_dict = rule.contents.to_dict()["rule"]
    min_stack_version = target_version or rule.contents.metadata.min_stack_version or "8.3.0"
    min_stack_version = Version.parse(min_stack_version, optional_minor_and_patch=True)
    rule_dict.setdefault("meta", {}).update(rule.contents.metadata.to_dict())

    if replace_id:
        rule_dict["rule_id"] = str(uuid4())

    rule_dict = downgrade(rule_dict, target_version=str(min_stack_version))
    meta = rule_dict.pop("meta")
    rule_contents_dict = {"rule": rule_dict, "metadata": meta}

    if rule.contents.transform:
        rule_contents_dict["transform"] = rule.contents.transform.to_dict()

    rule_contents = TOMLRuleContents.from_dict(rule_contents_dict)
    payload = rule_contents.to_api_format(include_metadata=include_metadata)
    return strip_non_public_fields(min_stack_version, payload)


def set_eql_config(min_stack_version_val: str) -> eql.parser.ParserConfig:
    """Based on the rule version set the eql functions allowed."""
    if min_stack_version_val:
        min_stack_version = Version.parse(min_stack_version_val, optional_minor_and_patch=True)
    else:
        min_stack_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)

    config = eql.parser.ParserConfig()

    for feature, version_range in definitions.ELASTICSEARCH_EQL_FEATURES.items():
        if version_range[0] <= min_stack_version <= (version_range[1] or min_stack_version):
            config.context[feature] = True  # type: ignore[reportUnknownMemberType]

    return config


def get_unique_query_fields(rule: TOMLRule) -> list[str] | None:
    """Get a list of unique fields used in a rule query from rule contents."""
    contents = rule.contents.to_api_format()
    language = contents.get("language")
    query = contents.get("query")
    if language not in ("kuery", "eql"):
        return None

    # remove once py-eql supports ipv6 for cidrmatch

    min_stack_version = rule.contents.metadata.get("min_stack_version")
    if not min_stack_version:
        raise ValueError("Min stack version not found")
    cfg = set_eql_config(min_stack_version)
    with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions, eql.parser.skip_optimizations, cfg:
        parsed = (  # type: ignore[reportUnknownVariableType]
            kql.parse(query, normalize_kql_keywords=RULES_CONFIG.normalize_kql_keywords)  # type: ignore[reportUnknownMemberType]
            if language == "kuery"
            else eql.parse_query(query)  # type: ignore[reportUnknownMemberType]
        )
    return sorted({str(f) for f in parsed if isinstance(f, (eql.ast.Field | kql.ast.Field))})  # type: ignore[reportUnknownVariableType]


def parse_datasets(datasets: list[str], package_manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Parses datasets into packaged integrations from rule data."""
    packaged_integrations: list[dict[str, Any]] = []
    for _value in sorted(datasets):
        # cleanup extra quotes pulled from ast field
        value = _value.strip('"')

        integration = "Unknown"
        if "." in value:
            package, integration = value.split(".", 1)
            # Handle cases where endpoint event datasource needs to be parsed uniquely (e.g endpoint.events.network)
            # as endpoint.network
            if package == "endpoint" and "events" in integration:
                integration = integration.split(".")[1]
        else:
            package = value

        if package in package_manifest:
            packaged_integrations.append({"package": package, "integration": integration})
    return packaged_integrations


# avoid a circular import
from .rule_validators import EQLValidator, ESQLValidator, KQLValidator  # noqa: E402
