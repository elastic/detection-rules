# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Offline ES|QL parser and AST for Elastic Security detection-rules."""

from . import ast
from .analyzer import analyze, check_catalog_names, infer_column_types
from .errors import (
    EsqlError,
    EsqlNestedQueryError,
    EsqlSchemaError,
    EsqlSemanticError,
    EsqlSyntaxError,
    EsqlTypeMismatchError,
    EsqlUnsupportedTypeError,
    EsqlVersionError,
)
from .features import ESQL_FEATURES
from .functions import (
    FUNCTIONS,
    NESTED_QUERY_FUNCTIONS,
    FunctionSignature,
    get_signature,
    has_function_catalog,
    is_known_command,
    is_known_function,
)
from .parser import parse_expression, parse_query, render, validate_nested_queries
from .release_window import format_es_compat
from .rule_semantics import validate_detection_rule_query
from .schema import Schema
from .types import comparison_family, types_comparable, types_orderable
from .utils import ParserConfig, get_config_value, get_current_config
from .verifier import verify_features
from .walkers import (
    ConfigurableWalker,
    DepthFirstWalker,
    EventDataset,
    RecursiveWalker,
    Walker,
    find_nested_queries,
    get_datasets_and_modules,
    get_defined_columns,
    get_event_datasets,
    get_field_names,
    get_from_source_groups,
    get_from_sources,
    get_keep_columns,
    get_metadata_fields,
    get_stats_grouping_fields,
    get_unique_fields,
    has_keep,
    is_aggregate_query,
)

__version__ = "0.1.0"
# Derived from esql/_antlr/*/provenance.json — do not hardcode; CI enforces sync.
__es_compat__ = format_es_compat()

__all__ = (
    "__version__",
    "__es_compat__",
    "ESQL_FEATURES",
    "FUNCTIONS",
    "NESTED_QUERY_FUNCTIONS",
    "ConfigurableWalker",
    "DepthFirstWalker",
    "EsqlError",
    "EsqlNestedQueryError",
    "EsqlSchemaError",
    "EsqlSemanticError",
    "EsqlSyntaxError",
    "EsqlTypeMismatchError",
    "EsqlUnsupportedTypeError",
    "EsqlVersionError",
    "EventDataset",
    "FunctionSignature",
    "ParserConfig",
    "RecursiveWalker",
    "Schema",
    "Walker",
    "analyze",
    "check_catalog_names",
    "comparison_family",
    "get_signature",
    "has_function_catalog",
    "infer_column_types",
    "is_known_command",
    "is_known_function",
    "ast",
    "types_comparable",
    "types_orderable",
    "find_nested_queries",
    "get_config_value",
    "get_current_config",
    "get_datasets_and_modules",
    "get_defined_columns",
    "get_event_datasets",
    "get_field_names",
    "get_from_sources",
    "get_from_source_groups",
    "get_keep_columns",
    "get_metadata_fields",
    "get_stats_grouping_fields",
    "get_unique_fields",
    "has_keep",
    "is_aggregate_query",
    "parse_expression",
    "parse_query",
    "render",
    "validate_detection_rule_query",
    "validate_nested_queries",
    "verify_features",
)
