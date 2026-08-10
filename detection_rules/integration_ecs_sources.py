# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Derive the fields an integration package populates outside its field definitions.

A package's `fields/*.yml` files are not a complete account of what its data streams
produce: ingest pipelines add fields at index time (enrichment processors, renames,
grok captures), and Elastic Agent stamps its own metadata onto every event. Those
fields are absent from `ecs.yml`, so ECS-scoped query validation would reject them
even though the integration populates them.

Two sources inside the package archive are parsed here, both versioned with the
package itself:

* `data_stream/<name>/elasticsearch/ingest_pipeline/*.yml` — every field an ingest
  processor writes to.
* `data_stream/<name>/sample_event.json` — a real document from the data stream, so
  every field in it is proof the data stream populates that field.

Only field names are returned. Callers decide which of them are ECS (see
`integrations.parse_version_schema`, which stores the ECS subset as `_ecs_populated`).
"""

import fnmatch
import json
import re
import zipfile
from pathlib import Path
from typing import Any

import yaml

PIPELINE_FILE_PATTERN = "*/data_stream/*/elasticsearch/ingest_pipeline/*.yml"
SAMPLE_EVENT_FILE_PATTERN = "*/data_stream/*/sample_event.json"

# Processors that generate a set of subfields under their target, rather than a single field.
GEO_SUBFIELDS = (
    "city_name",
    "continent_code",
    "continent_name",
    "country_iso_code",
    "country_name",
    "location",
    "name",
    "postal_code",
    "region_iso_code",
    "region_name",
    "timezone",
)
USER_AGENT_SUBFIELDS = (
    "device.name",
    "name",
    "original",
    "os.full",
    "os.name",
    "os.platform",
    "os.version",
    "version",
)
DOMAIN_SUBFIELDS = ("domain", "registered_domain", "subdomain", "top_level_domain")
URL_SUBFIELDS = (
    "domain",
    "extension",
    "fragment",
    "original",
    "password",
    "path",
    "port",
    "query",
    "scheme",
    "username",
)
EXPANDING_PROCESSORS: dict[str, tuple[str | None, tuple[str, ...]]] = {
    # processor type -> (default target_field, subfields written under the target)
    "geoip": ("geoip", GEO_SUBFIELDS),
    "ip_location": ("geo", GEO_SUBFIELDS),
    "user_agent": ("user_agent", USER_AGENT_SUBFIELDS),
    "uri_parts": ("url", URL_SUBFIELDS),
    "registered_domain": (None, DOMAIN_SUBFIELDS),
}

# Processors that transform a field in place: `field` is the target unless `target_field`
# redirects the output elsewhere. An in-place transform still means the data stream carries
# the field, so `field` counts as populated.
IN_PLACE_PROCESSORS = (
    "append",
    "convert",
    "dot_expander",
    "gsub",
    "join",
    "lowercase",
    "set",
    "split",
    "trim",
    "uppercase",
    "urldecode",
)

# Processors whose `field` is only an input: they write to `target_field`, defaulting to the
# mapped field (or nothing) when it is omitted. `field` must not be counted here — a rename
# moves its source field away, so treating it as populated would be wrong.
TARGET_ONLY_PROCESSORS: dict[str, str | None] = {
    "community_id": "network.community_id",
    "date": "@timestamp",
    "enrich": None,
    "fingerprint": "fingerprint",
    "json": None,
    "kv": None,
    "network_direction": "network.direction",
    "rename": None,
}

FIELD_NAME_RE = re.compile(r"^@?[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_@]+)*$")
GROK_CAPTURE_RE = re.compile(r"%\{[A-Z0-9_]+:([^:}]+)")
DISSECT_KEY_RE = re.compile(r"%\{([^}]*)\}")
SCRIPT_CTX_DOT_RE = re.compile(r"ctx\.((?:[a-zA-Z0-9_]+\??\.)*[a-zA-Z0-9_]+)")
SCRIPT_CTX_BRACKET_RE = re.compile(r"ctx((?:\[['\"][a-zA-Z0-9_.@]+['\"]\])+)")
BRACKET_KEY_RE = re.compile(r"['\"]([a-zA-Z0-9_.@]+)['\"]")


def _add_field(fields: set[str], name: Any) -> None:
    """Add a candidate field name, discarding anything that is not a plain dotted path."""
    if isinstance(name, str) and FIELD_NAME_RE.match(name):
        fields.add(name)


def _clean_dissect_key(key: str) -> str:
    """Strip dissect modifiers (`+`, `?`, `*`, `&`, `->`, `/n`) from a key."""
    key = key.removesuffix("->").lstrip("+?*&")
    return key.split("/", 1)[0].strip()


def _collect_expanded_targets(fields: set[str], proc_type: str, body: dict[str, Any]) -> None:
    """Add the subfields a multi-output processor writes under its target."""
    default_target, subfields = EXPANDING_PROCESSORS[proc_type]
    target = body.get("target_field", default_target)
    if not isinstance(target, str) or not target:
        return
    for subfield in subfields:
        _add_field(fields, f"{target}.{subfield}")


def _collect_parsed_targets(fields: set[str], proc_type: str, body: dict[str, Any]) -> None:
    """Add the fields a parsing processor captures out of a string."""
    if proc_type == "grok":
        patterns: Any = body.get("patterns") or []
        for pattern in patterns if isinstance(patterns, list) else []:  # type: ignore[reportUnknownVariableType]
            if isinstance(pattern, str):
                for capture in GROK_CAPTURE_RE.findall(pattern):
                    _add_field(fields, capture)
    elif proc_type == "dissect":
        pattern = body.get("pattern")
        if isinstance(pattern, str):
            for key in DISSECT_KEY_RE.findall(pattern):
                _add_field(fields, _clean_dissect_key(key))
    elif proc_type == "script":
        source = body.get("source")
        if isinstance(source, str):
            for match in SCRIPT_CTX_DOT_RE.findall(source):
                _add_field(fields, match.replace("?", ""))
            for match in SCRIPT_CTX_BRACKET_RE.findall(source):
                _add_field(fields, ".".join(BRACKET_KEY_RE.findall(match)))


def collect_processor_targets(processors: Any, fields: set[str]) -> None:
    """Recursively collect every field the given processors write to."""
    if not isinstance(processors, list):
        return
    for processor in processors:  # type: ignore[reportUnknownVariableType]
        if not isinstance(processor, dict):
            continue
        for proc_type, raw_body in processor.items():  # type: ignore[reportUnknownVariableType]
            body: dict[str, Any] = dict(raw_body) if isinstance(raw_body, dict) else {}  # type: ignore[reportUnknownArgumentType]

            if proc_type in EXPANDING_PROCESSORS:
                _collect_expanded_targets(fields, proc_type, body)  # type: ignore[reportUnknownArgumentType]
            elif proc_type in IN_PLACE_PROCESSORS:
                _add_field(fields, body.get("target_field") or body.get("field"))
            elif proc_type in TARGET_ONLY_PROCESSORS:
                _add_field(fields, body.get("target_field") or TARGET_ONLY_PROCESSORS[proc_type])  # type: ignore[reportUnknownArgumentType]
            else:
                _collect_parsed_targets(fields, proc_type, body)  # type: ignore[reportUnknownArgumentType]

            if proc_type == "foreach":
                collect_processor_targets([body.get("processor")], fields)

            # processors may nest their own error handlers
            collect_processor_targets(body.get("on_failure"), fields)


def extract_pipeline_fields(zip_ref: zipfile.ZipFile) -> dict[str, set[str]]:
    """Map each data stream to the fields its ingest pipelines write to."""
    pipeline_fields: dict[str, set[str]] = {}

    for file in zip_ref.namelist():
        if not fnmatch.fnmatch(file, PIPELINE_FILE_PATTERN):
            continue
        data_stream = Path(file).parents[2].name
        try:
            pipeline = yaml.safe_load(zip_ref.read(file))
        except yaml.YAMLError:
            # a pipeline we cannot parse simply contributes nothing
            continue
        if not isinstance(pipeline, dict):
            continue

        fields = pipeline_fields.setdefault(data_stream, set())
        collect_processor_targets(pipeline.get("processors"), fields)  # type: ignore[reportUnknownMemberType]
        collect_processor_targets(pipeline.get("on_failure"), fields)  # type: ignore[reportUnknownMemberType]

    return pipeline_fields


def flatten_document(document: dict[str, Any], prefix: str = "") -> set[str]:
    """Flatten a document into dotted leaf field names."""
    fields: set[str] = set()
    for key, value in document.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            fields.update(flatten_document(value, f"{name}."))  # type: ignore[reportUnknownArgumentType]
        elif isinstance(value, list):
            # a list of objects still contributes its leaves; a list of scalars is the field
            for item in value:  # type: ignore[reportUnknownVariableType]
                if isinstance(item, dict):
                    fields.update(flatten_document(item, f"{name}."))  # type: ignore[reportUnknownArgumentType]
                else:
                    fields.add(name)
        else:
            fields.add(name)
    return fields


def extract_sample_event_fields(zip_ref: zipfile.ZipFile) -> dict[str, set[str]]:
    """Map each data stream to the fields present in its sample event."""
    sample_fields: dict[str, set[str]] = {}

    for file in zip_ref.namelist():
        if not fnmatch.fnmatch(file, SAMPLE_EVENT_FILE_PATTERN):
            continue
        data_stream = Path(file).parent.name
        try:
            sample_event = json.loads(zip_ref.read(file))
        except json.JSONDecodeError:
            continue
        if not isinstance(sample_event, dict):
            continue

        sample_fields.setdefault(data_stream, set()).update(flatten_document(sample_event))  # type: ignore[reportUnknownArgumentType]

    return sample_fields


def extract_populated_fields(zip_ref: zipfile.ZipFile) -> dict[str, set[str]]:
    """Map each data stream to the fields the package populates outside its field definitions."""
    populated_fields: dict[str, set[str]] = {}
    for source in (extract_pipeline_fields(zip_ref), extract_sample_event_fields(zip_ref)):
        for data_stream, fields in source.items():
            populated_fields.setdefault(data_stream, set()).update(fields)
    return populated_fields
