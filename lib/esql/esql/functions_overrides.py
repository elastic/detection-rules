# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Hand overrides on top of generated ES|QL function signatures.

Overrides win over `esql/_generated/<module>.zip` signatures. Keep this
file small — prefer fixing the generator when ES definitions are wrong.

Entries in `SIGNATURE_OVERRIDE_SPECS` use the same JSON shape as generated
signatures (`min_args`, `max_args`, `arg_groups`, `return_type`).
"""

from __future__ import annotations

from typing import Any

__all__ = (
    "EXTRA_KNOWN_FUNCTIONS",
    "NESTED_QUERY_FUNCTION_NAMES",
    "SIGNATURE_OVERRIDE_SPECS",
)

# Force nested-query treatment regardless of generated metadata.
NESTED_QUERY_FUNCTION_NAMES: frozenset[str] = frozenset({"kql", "eql"})

# Names treated as known even when absent from a given stack's generated map
# (constants / legacy aliases).
EXTRA_KNOWN_FUNCTIONS: frozenset[str] = frozenset({"e", "pi", "point", "host"})

# Intentional arity / family tweaks. `eql` is not always in kibana/generated.
SIGNATURE_OVERRIDE_SPECS: dict[str, dict[str, Any]] = {
    "kql": {
        "min_args": 1,
        "max_args": 2,
        "arg_groups": [["string"], ["unknown"]],
        "return_type": "boolean",
    },
    "eql": {
        "min_args": 1,
        "max_args": 2,
        "arg_groups": [["string"], ["unknown"]],
        "return_type": "boolean",
    },
}
