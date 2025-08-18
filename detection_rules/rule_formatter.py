# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Helper functions for managing rules in the repository."""

import copy
import dataclasses
import json
import textwrap
from collections import OrderedDict
from collections.abc import Iterable
from pathlib import Path
from typing import Any, TextIO

import toml

from .schemas import definitions
from .utils import cached

SQ = "'"
DQ = '"'
TRIPLE_SQ = SQ * 3
TRIPLE_DQ = DQ * 3


@cached
def get_preserved_fmt_fields() -> set[str]:
    from .rule import BaseRuleData

    preserved_keys: set[str] = set()

    for field in dataclasses.fields(BaseRuleData):
        if field.type in (definitions.Markdown, definitions.Markdown | None):
            preserved_keys.add(field.metadata.get("data_key", field.name))
    return preserved_keys


def cleanup_whitespace(val: Any) -> Any:
    if isinstance(val, str):
        return " ".join(line.strip() for line in val.strip().splitlines())
    return val


def nested_normalize(d: Any, skip_cleanup: bool = False) -> Any:
    preserved_fields = get_preserved_fmt_fields()

    if isinstance(d, str):
        return d if skip_cleanup else cleanup_whitespace(d)
    if isinstance(d, list):
        return [nested_normalize(val) for val in d]  # type: ignore[reportUnknownVariableType]
    if isinstance(d, dict):
        for k, v in d.items():  # type: ignore[reportUnknownVariableType]
            if k == "query":
                # the linter still needs some work, but once up to par, uncomment to implement - kql.lint(v)
                # do not normalize queries
                d.update({k: v})  # type: ignore[reportUnknownMemberType]
            elif k in preserved_fields:
                # let these maintain newlines and whitespace for markdown support
                d.update({k: nested_normalize(v, skip_cleanup=True)})  # type: ignore[reportUnknownMemberType]
            else:
                d.update({k: nested_normalize(v)})  # type: ignore[reportUnknownMemberType]
        return d  # type: ignore[reportUnknownVariableType]
    return d


def wrap_text(v: str, block_indent: int = 0) -> list[str]:
    """Block and indent a blob of text."""
    v = " ".join(v.split())
    lines = textwrap.wrap(
        v,
        initial_indent=" " * block_indent,
        subsequent_indent=" " * block_indent,
        width=120,
        break_long_words=False,
        break_on_hyphens=False,
    )
    lines = [line + "\n" for line in lines]
    # If there is a single line that contains a quote, add a new blank line to trigger multiline formatting
    if len(lines) == 1 and '"' in lines[0]:
        lines = [*lines, ""]
    return lines


def wrap_text_and_join(v: str, block_indent: int = 0) -> str:
    lines = wrap_text(v, block_indent=block_indent)
    return "".join(lines)


class NonformattedField(str):  # noqa: SLOT000
    """Non-formatting class."""


def preserve_formatting_for_fields(data: OrderedDict[str, Any], fields_to_preserve: list[str]) -> OrderedDict[str, Any]:
    """Preserve formatting for specified nested fields in an action."""

    def apply_preservation(target: OrderedDict[str, Any], keys: list[str]) -> None:
        """Apply NonformattedField preservation based on keys path."""
        for key in keys[:-1]:
            # Iterate to the key, diving into nested dictionaries
            if key in target and isinstance(target[key], dict):
                target = target[key]
            else:
                # Cannot preserve formatting for missing or non-dict intermediate
                return

        final_key = keys[-1]
        if final_key in target:
            # Apply NonformattedField to the target field if it exists
            target[final_key] = NonformattedField(target[final_key])

    for field_path in fields_to_preserve:
        keys = field_path.split(".")
        apply_preservation(data, keys)

    return data


class RuleTomlEncoder(toml.TomlEncoder):  # type: ignore[reportMissingTypeArgument]
    """Generate a pretty form of toml."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Create the encoder but override some default functions."""
        super().__init__(*args, **kwargs)  # type: ignore[reportUnknownMemberType]
        self._old_dump_list = toml.TomlEncoder().dump_funcs[list]
        self.dump_funcs[str] = self.dump_str
        self.dump_funcs[str] = self.dump_str
        self.dump_funcs[list] = self.dump_list
        self.dump_funcs[NonformattedField] = self.dump_str

    def dump_str(self, v: str | NonformattedField) -> str:
        """Change the TOML representation to multi-line or single quote when logical."""
        initial_newline = ["\n"]

        if isinstance(v, NonformattedField):
            # first line break is not forced like other multiline string dumps
            lines = v.splitlines(True)
            initial_newline = []

        else:
            lines = wrap_text(v)

        multiline = len(lines) > 1
        raw = (multiline or (DQ in v and SQ not in v)) and TRIPLE_DQ not in v

        if multiline:
            if raw:
                return "".join([TRIPLE_DQ, *initial_newline, *lines, TRIPLE_DQ])
            return "\n".join([TRIPLE_SQ] + [json.dumps(line)[1:-1] for line in lines] + [TRIPLE_SQ])
        if raw:
            return f"'{lines[0]:s}'"
        # In the toml library there is a magic replace for \\\\x -> u00 that we wish to avoid until #4979 is resolved
        # Also addresses an issue where backslashes in certain strings are not properly escaped in self._old_dump_str(v)
        return json.dumps(v)

    def _dump_flat_list(self, v: Iterable[Any]) -> str:
        """A slightly tweaked version of original dump_list, removing trailing commas."""
        if not v:
            return "[]"

        v_list = list(v)

        retval = "[" + str(self.dump_value(v_list[0])) + ","
        for u in v_list[1:]:
            retval += " " + str(self.dump_value(u)) + ","
        return retval.rstrip(",") + "]"

    def dump_list(self, v: Iterable[Any]) -> str:
        """Dump a list more cleanly."""
        if all(isinstance(d, str) for d in v) and sum(len(d) + 3 for d in v) > 100:  # noqa: PLR2004
            dump: list[str] = []
            for item in v:
                if len(item) > (120 - 4 - 3 - 3) and " " in item:
                    dump.append(f'    """\n{wrap_text_and_join(item, block_indent=4)}    """')
                else:
                    dump.append(" " * 4 + self.dump_value(item))
            return "[\n{},\n]".format(",\n".join(dump))

        if v and all(isinstance(i, dict) for i in v):
            # Compact inline format for lists of dictionaries with proper indentation
            retval = "\n" + " " * 2 + "[\n"
            retval += ",\n".join([" " * 4 + self.dump_inline_table(u).strip() for u in v])
            retval += "\n" + " " * 2 + "]\n"
            return retval

        return self._dump_flat_list(v)


def toml_write(rule_contents: dict[str, Any], out_file_path: Path | None = None) -> None:  # noqa: PLR0915
    """Write rule in TOML."""

    encoder = RuleTomlEncoder()
    contents = copy.deepcopy(rule_contents)

    def order_rule(obj: Any) -> Any:
        if isinstance(obj, dict):
            obj = OrderedDict(sorted(obj.items()))  # type: ignore[reportUnknownArgumentType, reportUnknownVariableType]
            for k, v in obj.items():
                if isinstance(v, dict | list):
                    obj[k] = order_rule(v)

        if isinstance(obj, list):
            for i, v in enumerate(obj):  # type: ignore[reportUnknownMemberType]
                if isinstance(v, dict | list):
                    obj[i] = order_rule(v)
            obj = sorted(obj, key=lambda x: json.dumps(x))  # type: ignore[reportUnknownArgumentType, reportUnknownVariableType]

        return obj

    def _do_write(f: TextIO | None, _data: str, _contents: dict[str, Any]) -> None:  # noqa: PLR0912
        query = None
        threat_query = None

        if _data == "rule":
            # - We want to avoid the encoder for the query and instead use kql-lint.
            # - Linting is done in rule.normalize() which is also called in rule.validate().
            # - Until lint has tabbing, this is going to result in all queries being flattened with no wrapping,
            #     but will at least purge extraneous white space
            query = contents["rule"].pop("query", "").strip()

            # - As tags are expanding, we may want to reconsider the need to have them in alphabetical order
            threat_query = contents["rule"].pop("threat_query", "").strip()

        top: OrderedDict[str, Any] = OrderedDict()
        bottom: OrderedDict[str, Any] = OrderedDict()

        for k in sorted(_contents):
            v = _contents.pop(k)

            if k == "actions":
                # explicitly preserve formatting for message field in actions
                preserved_fields = ["params.message"]
                v = [preserve_formatting_for_fields(action, preserved_fields) for action in v] if v is not None else []

            if k == "filters":
                # explicitly preserve formatting for value field in filters
                preserved_fields = ["meta.value"]
                v = [preserve_formatting_for_fields(meta, preserved_fields) for meta in v] if v is not None else []

            if k == "note" and isinstance(v, str):
                # Transform instances of \ to \\ as calling write will convert \\ to \.
                # This will ensure that the output file has the correct number of backslashes.
                v = v.replace("\\", "\\\\")

            if k == "setup" and isinstance(v, str):
                # Transform instances of \ to \\ as calling write will convert \\ to \.
                # This will ensure that the output file has the correct number of backslashes.
                v = v.replace("\\", "\\\\")

            if k == "description" and isinstance(v, str):
                # Transform instances of \ to \\ as calling write will convert \\ to \.
                # This will ensure that the output file has the correct number of backslashes.
                v = v.replace("\\", "\\\\")

            if k == "osquery" and isinstance(v, list):
                # Specifically handle transform.osquery queries
                for osquery_item in v:  # type: ignore[reportUnknownVariableType]
                    if "query" in osquery_item and isinstance(osquery_item["query"], str):
                        # Transform instances of \ to \\ as calling write will convert \\ to \.
                        # This will ensure that the output file has the correct number of backslashes.
                        osquery_item["query"] = osquery_item["query"].replace("\\", "\\\\")  # type: ignore[reportUnknownMemberType]

            if isinstance(v, dict):
                bottom[k] = OrderedDict(sorted(v.items()))  # type: ignore[reportUnknownArgumentType]
            elif isinstance(v, list):
                if any(isinstance(value, (dict | list)) for value in v):  # type: ignore[reportUnknownArgumentType]
                    bottom[k] = v
                else:
                    top[k] = v
            elif k in get_preserved_fmt_fields():
                top[k] = NonformattedField(v)
            else:
                top[k] = v

        if query:
            top.update({"query": "XXxXX"})  # type: ignore[reportUnknownMemberType]

        if threat_query:
            top.update({"threat_query": "XXxXX"})  # type: ignore[reportUnknownMemberType]

        top.update(bottom)  # type: ignore[reportUnknownMemberType]
        top_out = toml.dumps(OrderedDict({data: top}), encoder=encoder)  # type: ignore[reportUnknownMemberType]

        # we want to preserve the threat_query format, but want to modify it in the context of encoded dump
        if threat_query:
            formatted_threat_query = "\nthreat_query = '''\n{}\n'''{}".format(threat_query, "\n\n" if bottom else "")
            top_out = top_out.replace('threat_query = "XXxXX"', formatted_threat_query)

        # we want to preserve the query format, but want to modify it in the context of encoded dump
        if query:
            formatted_query = "\nquery = '''\n{}\n'''{}".format(query, "\n\n" if bottom else "")
            top_out = top_out.replace('query = "XXxXX"', formatted_query)

        if f:
            _ = f.write(top_out + "\n")
        else:
            print(top_out)

    f = None
    if out_file_path:
        f = out_file_path.open("w")

    try:
        for data in ("metadata", "transform", "rule"):
            _contents = contents.get(data, {})
            if not _contents:
                continue
            order_rule(_contents)
            _do_write(f, data, _contents)
    finally:
        if f:
            f.close()
