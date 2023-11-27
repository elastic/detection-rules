# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Validation logic for rules containing queries."""
from functools import cached_property
from typing import List, Optional, Tuple, Union

import eql
from antlr4 import CommonTokenStream, InputStream, ParseTreeWalker, ParserRuleContext
from antlr4.tree.Trees import Trees


from semver import Version

import kql
from esql.EsqlBaseLexer import EsqlBaseLexer
from esql.EsqlBaseParser import EsqlBaseParser
from esql.EsqlBaseParserListener import EsqlBaseParserListener

from . import ecs, endgame
from .integrations import (get_integration_schema_data,
                           load_integrations_manifests)
from .misc import load_current_package_version
from .rule import (EQLRuleData, QueryRuleData, QueryValidator, RuleMeta,
                   TOMLRuleContents, set_eql_config)
from .schemas import get_stack_schemas

EQL_ERROR_TYPES = Union[eql.EqlCompileError,
                        eql.EqlError,
                        eql.EqlParseError,
                        eql.EqlSchemaError,
                        eql.EqlSemanticError,
                        eql.EqlSyntaxError,
                        eql.EqlTypeMismatchError]
KQL_ERROR_TYPES = Union[kql.KqlCompileError, kql.KqlParseError]


class KQLValidator(QueryValidator):
    """Specific fields for KQL query event types."""

    @cached_property
    def ast(self) -> kql.ast.Expression:
        return kql.parse(self.query)

    @cached_property
    def unique_fields(self) -> List[str]:
        return list(set(str(f) for f in self.ast if isinstance(f, kql.ast.Field)))

    def to_eql(self) -> eql.ast.Expression:
        return kql.to_eql(self.query)

    def validate(self, data: QueryRuleData, meta: RuleMeta) -> None:
        """Validate the query, called from the parent which contains [metadata] information."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            # syntax only, which is done via self.ast
            return

        if isinstance(data, QueryRuleData) and data.language != 'lucene':
            packages_manifest = load_integrations_manifests()
            package_integrations = TOMLRuleContents.get_packaged_integrations(data, meta, packages_manifest)

            validation_checks = {"stack": None, "integrations": None}
            # validate the query against fields within beats
            validation_checks["stack"] = self.validate_stack_combos(data, meta)

            if package_integrations:
                # validate the query against related integration fields
                validation_checks["integrations"] = self.validate_integration(data, meta, package_integrations)

            if (validation_checks["stack"] and not package_integrations):
                raise validation_checks["stack"]

            if (validation_checks["stack"] and validation_checks["integrations"]):
                raise ValueError(f"Error in both stack and integrations checks: {validation_checks}")

    def validate_stack_combos(self, data: QueryRuleData, meta: RuleMeta) -> Union[KQL_ERROR_TYPES, None, TypeError]:
        """Validate the query against ECS and beats schemas across stack combinations."""
        for stack_version, mapping in meta.get_validation_stack_versions().items():
            beats_version = mapping['beats']
            ecs_version = mapping['ecs']
            err_trailer = f'stack: {stack_version}, beats: {beats_version}, ecs: {ecs_version}'

            beat_types, beat_schema, schema = self.get_beats_schema(data.index or [],
                                                                    beats_version, ecs_version)

            try:
                kql.parse(self.query, schema=schema)
            except kql.KqlParseError as exc:
                message = exc.error_msg
                trailer = err_trailer
                if "Unknown field" in message and beat_types:
                    trailer = f"\nTry adding event.module or event.dataset to specify beats module\n\n{trailer}"

                return kql.KqlParseError(exc.error_msg, exc.line, exc.column, exc.source,
                                         len(exc.caret.lstrip()), trailer=trailer)
            except Exception as exc:
                print(err_trailer)
                return exc

    def validate_integration(self, data: QueryRuleData, meta: RuleMeta, package_integrations: List[dict]) -> Union[
            KQL_ERROR_TYPES, None, TypeError]:
        """Validate the query, called from the parent which contains [metadata] information."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            # syntax only, which is done via self.ast
            return

        error_fields = {}
        current_stack_version = ""
        combined_schema = {}
        for integration_schema_data in get_integration_schema_data(data, meta, package_integrations):
            ecs_version = integration_schema_data['ecs_version']
            integration = integration_schema_data['integration']
            package = integration_schema_data['package']
            package_version = integration_schema_data['package_version']
            integration_schema = integration_schema_data['schema']
            stack_version = integration_schema_data['stack_version']

            if stack_version != current_stack_version:
                # reset the combined schema for each stack version
                current_stack_version = stack_version
                combined_schema = {}

            # add non-ecs-schema fields for edge cases not added to the integration
            for index_name in data.index:
                integration_schema.update(**ecs.flatten(ecs.get_index_schema(index_name)))

            # add endpoint schema fields for multi-line fields
            integration_schema.update(**ecs.flatten(ecs.get_endpoint_schemas()))
            combined_schema.update(**integration_schema)

            try:
                # validate the query against the integration fields with the package version
                kql.parse(self.query, schema=integration_schema)
            except kql.KqlParseError as exc:
                if exc.error_msg == "Unknown field":
                    field = extract_error_field(exc)
                    trailer = (f"\n\tTry adding event.module or event.dataset to specify integration module\n\t"
                               f"Will check against integrations {meta.integration} combined.\n\t"
                               f"{package=}, {integration=}, {package_version=}, "
                               f"{stack_version=}, {ecs_version=}"
                               )
                    error_fields[field] = {"error": exc, "trailer": trailer}
                    if data.get("notify", False):
                        print(f"\nWarning: `{field}` in `{data.name}` not found in schema. {trailer}")
                else:
                    return kql.KqlParseError(exc.error_msg, exc.line, exc.column, exc.source,
                                             len(exc.caret.lstrip()), trailer=trailer)

        # don't error on fields that are in another integration schema
        for field in list(error_fields.keys()):
            if field in combined_schema:
                del error_fields[field]

        # raise the first error
        if error_fields:
            _, data = next(iter(error_fields.items()))
            exc = data["error"]
            trailer = data["trailer"]

            return kql.KqlParseError(exc.error_msg, exc.line, exc.column, exc.source,
                                     len(exc.caret.lstrip()), trailer=trailer)


class EQLValidator(QueryValidator):
    """Specific fields for EQL query event types."""

    @cached_property
    def ast(self) -> eql.ast.Expression:
        latest_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
        config = set_eql_config(str(latest_version))
        with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions, config:
            return eql.parse_query(self.query)

    def text_fields(self, eql_schema: Union[ecs.KqlSchema2Eql, endgame.EndgameSchema]) -> List[str]:
        """Return a list of fields of type text."""
        from kql.parser import elasticsearch_type_family
        schema = eql_schema.kql_schema if isinstance(eql_schema, ecs.KqlSchema2Eql) else eql_schema.endgame_schema

        return [f for f in self.unique_fields if elasticsearch_type_family(schema.get(f)) == 'text']

    @cached_property
    def unique_fields(self) -> List[str]:
        return list(set(str(f) for f in self.ast if isinstance(f, eql.ast.Field)))

    def validate(self, data: 'QueryRuleData', meta: RuleMeta) -> None:
        """Validate an EQL query while checking TOMLRule."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            # syntax only, which is done via self.ast
            return

        if isinstance(data, QueryRuleData) and data.language != 'lucene':
            packages_manifest = load_integrations_manifests()
            package_integrations = TOMLRuleContents.get_packaged_integrations(data, meta, packages_manifest)

            validation_checks = {"stack": None, "integrations": None}
            # validate the query against fields within beats
            validation_checks["stack"] = self.validate_stack_combos(data, meta)

            if package_integrations:
                # validate the query against related integration fields
                validation_checks["integrations"] = self.validate_integration(data, meta, package_integrations)

            if validation_checks["stack"] and not package_integrations:
                raise validation_checks["stack"]

            if validation_checks["stack"] and validation_checks["integrations"]:
                raise ValueError(f"Error in both stack and integrations checks: {validation_checks}")

            rule_type_config_fields, rule_type_config_validation_failed = \
                self.validate_rule_type_configurations(data, meta)
            if rule_type_config_validation_failed:
                raise ValueError(f"""Rule type config values are not ECS compliant, check these values:
                                 {rule_type_config_fields}""")

    def validate_stack_combos(self, data: QueryRuleData, meta: RuleMeta) -> Union[EQL_ERROR_TYPES, None, ValueError]:
        """Validate the query against ECS and beats schemas across stack combinations."""
        for stack_version, mapping in meta.get_validation_stack_versions().items():
            beats_version = mapping['beats']
            ecs_version = mapping['ecs']
            endgame_version = mapping['endgame']
            err_trailer = f'stack: {stack_version}, beats: {beats_version},' \
                          f'ecs: {ecs_version}, endgame: {endgame_version}'

            beat_types, beat_schema, schema = self.get_beats_schema(data.index or [],
                                                                    beats_version, ecs_version)
            endgame_schema = self.get_endgame_schema(data.index, endgame_version)
            eql_schema = ecs.KqlSchema2Eql(schema)

            # validate query against the beats and eql schema
            exc = self.validate_query_with_schema(data=data, schema=eql_schema, err_trailer=err_trailer,
                                                  beat_types=beat_types, min_stack_version=meta.min_stack_version)
            if exc:
                return exc

            if endgame_schema:
                # validate query against the endgame schema
                exc = self.validate_query_with_schema(data=data, schema=endgame_schema, err_trailer=err_trailer,
                                                      min_stack_version=meta.min_stack_version)
                if exc:
                    raise exc

    def validate_integration(self, data: QueryRuleData, meta: RuleMeta, package_integrations: List[dict]) -> Union[
            EQL_ERROR_TYPES, None, ValueError]:
        """Validate an EQL query while checking TOMLRule against integration schemas."""
        if meta.query_schema_validation is False or meta.maturity == "deprecated":
            # syntax only, which is done via self.ast
            return

        error_fields = {}
        current_stack_version = ""
        combined_schema = {}
        for integration_schema_data in get_integration_schema_data(data, meta, package_integrations):
            ecs_version = integration_schema_data['ecs_version']
            integration = integration_schema_data['integration']
            package = integration_schema_data['package']
            package_version = integration_schema_data['package_version']
            integration_schema = integration_schema_data['schema']
            stack_version = integration_schema_data['stack_version']

            if stack_version != current_stack_version:
                # reset the combined schema for each stack version
                current_stack_version = stack_version
                combined_schema = {}

            # add non-ecs-schema fields for edge cases not added to the integration
            for index_name in data.index:
                integration_schema.update(**ecs.flatten(ecs.get_index_schema(index_name)))

            # add endpoint schema fields for multi-line fields
            integration_schema.update(**ecs.flatten(ecs.get_endpoint_schemas()))
            combined_schema.update(**integration_schema)

            eql_schema = ecs.KqlSchema2Eql(integration_schema)
            err_trailer = f'stack: {stack_version}, integration: {integration},' \
                          f'ecs: {ecs_version}, package: {package}, package_version: {package_version}'

            exc = self.validate_query_with_schema(data=data, schema=eql_schema, err_trailer=err_trailer,
                                                  min_stack_version=meta.min_stack_version)

            if isinstance(exc, eql.EqlParseError):
                message = exc.error_msg
                if message == "Unknown field" or "Field not recognized" in message:
                    field = extract_error_field(exc)
                    trailer = (f"\n\tTry adding event.module or event.dataset to specify integration module\n\t"
                               f"Will check against integrations {meta.integration} combined.\n\t"
                               f"{package=}, {integration=}, {package_version=}, "
                               f"{stack_version=}, {ecs_version=}"
                               )
                    error_fields[field] = {"error": exc, "trailer": trailer}
                    if data.get("notify", False):
                        print(f"\nWarning: `{field}` in `{data.name}` not found in schema. {trailer}")
                else:
                    return exc

        # don't error on fields that are in another integration schema
        for field in list(error_fields.keys()):
            if field in combined_schema:
                del error_fields[field]

        # raise the first error
        if error_fields:
            _, data = next(iter(error_fields.items()))
            exc = data["error"]
            return exc

    def validate_query_with_schema(self, data: 'QueryRuleData', schema: Union[ecs.KqlSchema2Eql, endgame.EndgameSchema],
                                   err_trailer: str, min_stack_version: str, beat_types: list = None) -> Union[
            EQL_ERROR_TYPES, ValueError, None]:
        """Validate the query against the schema."""
        try:
            config = set_eql_config(min_stack_version)
            with config, schema, eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
                eql.parse_query(self.query)
        except eql.EqlParseError as exc:
            message = exc.error_msg
            trailer = err_trailer
            if "Unknown field" in message and beat_types:
                trailer = f"\nTry adding event.module or event.dataset to specify beats module\n\n{trailer}"
            elif "Field not recognized" in message:
                text_fields = self.text_fields(schema)
                if text_fields:
                    fields_str = ', '.join(text_fields)
                    trailer = f"\neql does not support text fields: {fields_str}\n\n{trailer}"

            return exc.__class__(exc.error_msg, exc.line, exc.column, exc.source,
                                 len(exc.caret.lstrip()), trailer=trailer)

        except Exception as exc:
            print(err_trailer)
            return exc

    def validate_rule_type_configurations(self, data: EQLRuleData, meta: RuleMeta) -> \
            Tuple[List[Optional[str]], bool]:
        """Validate EQL rule type configurations."""
        if data.timestamp_field or data.event_category_override or data.tiebreaker_field:

            # get a list of rule type configuration fields
            # Get a list of rule type configuration fields
            fields = ["timestamp_field", "event_category_override", "tiebreaker_field"]
            set_fields = list(filter(None, (data.get(field) for field in fields)))

            # get stack_version and ECS schema
            min_stack_version = meta.get("min_stack_version")
            if min_stack_version is None:
                min_stack_version = Version.parse(load_current_package_version(), optional_minor_and_patch=True)
            ecs_version = get_stack_schemas()[str(min_stack_version)]['ecs']
            schema = ecs.get_schema(ecs_version)

            # return a list of rule type config field values and whether any are not in the schema
            return (set_fields, any([f not in schema.keys() for f in set_fields]))
        else:
            # if rule type fields are not set, return an empty list and False
            return [], False


class ESQLSyntaxError(Exception):
    """Exception raised for syntax/semantic errors of an ESQL query."""

    def __init__(self, message):
        super().__init__(message)


class ESQLValidatorListener(EsqlBaseParserListener):
    def __init__(self, schema):
        self.schema = schema
        self.field_list = []
        self.indices = []

    def enterQualifiedName(self, ctx: EsqlBaseParser.QualifiedNameContext):  # noqa: N802
        """Extract field from context (ctx)."""

        if not isinstance(ctx.parentCtx, EsqlBaseParser.EvalCommandContext):
            field = ctx.getText()
            self.field_list.append(field)

            if field not in self.schema:
                raise ESQLSyntaxError(f"Invalid field: {field}")

    def enterSourceIdentifier(self, ctx: EsqlBaseParser.SourceIdentifierContext):  # noqa: N802
        """Extract index and fields from context (ctx)."""

        # Check if the parent context is NOT 'FromCommandContext'
        if not isinstance(ctx.parentCtx, EsqlBaseParser.FromCommandContext):
            # Extract field from context (ctx)
            # The implementation depends on your parse tree structure
            # For example, if the field name is directly the text of this context:
            field = ctx.getText()
            self.field_list.append(field)

            if field not in self.schema:
                raise ValueError(f"Invalid field: {field}")
        else:
            # check index against integrations?
            self.indices.append(ctx.getText())

    def check_literal_type(self, ctx: ParserRuleContext):
        """Check the type of a literal against the schema."""
        field, context_type = self.find_associated_field_and_context(ctx)

        if field and field in self.schema:
            expected_type = self.schema[field]
            actual_type = self.get_literal_type(ctx, context_type)

            if expected_type != actual_type:
                raise ValueError(f"Field '{field}' in context '{context_type}'"
                                 f"expects type '{expected_type}', but got '{actual_type}'")

    def find_associated_field_and_context(self, ctx: ParserRuleContext):
        """Find the field and context type associated with a literal."""
        parent_ctx = ctx.parentCtx
        while parent_ctx:
            if isinstance(parent_ctx, EsqlBaseParser.ComparisonContext):
                # Adjust this logic based on your parse tree structure
                # Example: If the field name is the text of the first child of the operator expression
                field_ctx = parent_ctx.operatorExpression(0).getChild(0)
                field = field_ctx.getText() if field_ctx else None
                return field, 'Comparison'
            elif isinstance(parent_ctx, EsqlBaseParser.LogicalInContext):
                field_ctx = parent_ctx.valueExpression(0).getChild(0)
                return field_ctx.getText() if field_ctx else None, 'LogicalIn'
            # Add additional conditions for other contexts where constants appear
            parent_ctx = parent_ctx.parentCtx
        return None, None

    def get_literal_type(self, ctx: ParserRuleContext, context_type: str):
        """Get the type of a literal."""
        # Determine the type of the literal based on the context type
        if context_type == 'Comparison' or context_type == 'LogicalIn':
            if isinstance(ctx, EsqlBaseParser.StringLiteralContext):
                return 'keyword'  # currently a 'string'
            elif isinstance(ctx, (EsqlBaseParser.IntegerLiteralContext, EsqlBaseParser.QualifiedIntegerLiteralContext)):
                return 'integer'
            elif isinstance(ctx, EsqlBaseParser.DecimalLiteralContext):
                return 'decimal'
            elif isinstance(ctx, EsqlBaseParser.BooleanLiteralContext):
                return 'boolean'
            # Add more conditions based on context_type and other types of literals as needed
        else:
            return 'unknown'

    # Override methods to use check_literal_type
    def enterNullLiteral(self, ctx: EsqlBaseParser.NullLiteralContext):  # noqa: N802
        """Check the type of a null literal against the schema."""
        self.check_literal_type(ctx)

    def enterQualifiedIntegerLiteral(self, ctx: EsqlBaseParser.QualifiedIntegerLiteralContext):  # noqa: N802
        """Check the type of a qualified integer literal against the schema."""
        self.check_literal_type(ctx)

    def enterDecimalLiteral(self, ctx: EsqlBaseParser.DecimalLiteralContext):  # noqa: N802
        """Check the type of a decimal literal against the schema."""
        self.check_literal_type(ctx)

    def enterIntegerLiteral(self, ctx: EsqlBaseParser.IntegerLiteralContext):  # noqa: N802
        """Check the type of an integer literal against the schema."""
        self.check_literal_type(ctx)

    def enterBooleanLiteral(self, ctx: EsqlBaseParser.BooleanLiteralContext):  # noqa: N802
        """Check the type of a boolean literal against the schema."""
        self.check_literal_type(ctx)

    def enterStringLiteral(self, ctx: EsqlBaseParser.StringLiteralContext):  # noqa: N802
        """Check the type of a string literal against the schema."""
        self.check_literal_type(ctx)

    def enterNumericArrayLiteral(self, ctx: EsqlBaseParser.NumericArrayLiteralContext):  # noqa: N802
        """Check the type of a numeric array literal against the schema."""
        self.check_literal_type(ctx)

    def enterBooleanArrayLiteral(self, ctx: EsqlBaseParser.BooleanArrayLiteralContext):  # noqa: N802
        """Check the type of a boolean array literal against the schema."""
        self.check_literal_type(ctx)

    def enterStringArrayLiteral(self, ctx: EsqlBaseParser.StringArrayLiteralContext):  # noqa: N802
        """Check the type of a string array literal against the schema."""
        self.check_literal_type(ctx)


class ESQLValidator(QueryValidator):
    """Validate specific fields for ESQL query event types."""

    field_list = []
    indices = []

    @cached_property
    def parser(self):
        """Return a parser instance."""
        input_stream = InputStream(self.query)
        lexer = EsqlBaseLexer(input_stream)
        token_stream = CommonTokenStream(lexer)
        return EsqlBaseParser(token_stream)

    def print_tree(self, ctx: ParserRuleContext):
        """Print the parse tree."""
        print(Trees.toStringTree(ctx, None, self.parser))

    def pretty_print_tree(self, ctx: EsqlBaseParser.SingleStatementContext, indent: int = 0, is_last: bool = True):
        """Pretty print the parse tree."""
        if ctx is None:
            return

        # Indentation and prefix logic
        indent_str = '    ' * indent
        prefix = '└── ' if is_last else '├── '

        # Print the current context
        node_label = type(ctx).__name__ + ': ' + ctx.getText()
        print(f"{indent_str}{prefix}{node_label}")

        # Recursively pretty print each child
        children = [ctx.getChild(i) for i in range(ctx.getChildCount())]
        for i, child in enumerate(children):
            self.pretty_print_tree(child, indent + 1, i == len(children) - 1)

    @cached_property
    def unique_fields(self) -> List[str]:
        """Return a list of unique fields in the query."""
        # return empty list for ES|QL rules until ast is available
        return set(self.field_list)

    def get_node(self, tree: EsqlBaseParser.SingleStatementContext, ctx: ParserRuleContext):
        """Return the first node of type ctx in the tree."""
        # fail if ctx is not a valid context
        if not issubclass(ctx, ParserRuleContext):
            raise ValueError(f"Invalid context: {ctx}")

        for child in tree.children:
            if isinstance(child, ctx):
                return child
            elif hasattr(child, "children"):
                return self.get_node(child, ctx)
            else:
                continue

        raise ESQLSyntaxError("No source command found")

    def validate(self, data: 'QueryRuleData', meta: RuleMeta) -> None:
        """Validate an ESQL query while checking TOMLRule."""

        if Version.parse(meta.min_stack_version) < Version.parse("8.11.0"):
            raise ESQLSyntaxError(f"Rule minstack must be greater than 8.10.0 {data.rule_id}")

        parser = self.parser
        tree = parser.singleStatement()
        self.pretty_print_tree(tree)

        # Create an instance of the listener with schema
        current_stack_version = ""
        combined_schema = {}
        # packages_manifest = load_integrations_manifests()
        # package_integrations = TOMLRuleContents.get_packaged_integrations(data, meta, packages_manifest)
        package_integrations = [{"package": "endpoint", "integration": None}]
        for integration_schema_data in get_integration_schema_data(data, meta, package_integrations):
            integration_schema = integration_schema_data['schema']
            stack_version = integration_schema_data['stack_version']

            if stack_version != current_stack_version:
                # reset the combined schema for each stack version
                current_stack_version = stack_version
                combined_schema = {}

            # setup listener
            index_listener = ESQLValidatorListener(combined_schema)

            # Walk the tree with the listener
            index_walker = ParseTreeWalker()
            # Trees.toStringTree(tree.children[0].children[0].children[0].children[0], None, parser)
            source_command = self.get_node(tree, EsqlBaseParser.SourceIdentifierContext)
            index_walker.enterRule(index_listener, source_command)

            # add non-ecs-schema fields for edge cases not added to the integration
            for index_name in index_listener.indices:
                integration_schema.update(**ecs.flatten(ecs.get_index_schema(index_name)))

            # add endpoint schema fields for multi-line fields
            integration_schema.update(**ecs.flatten(ecs.get_endpoint_schemas()))
            combined_schema.update(**integration_schema)

            # setup listener
            listener = ESQLValidatorListener(combined_schema)

            # Walk the tree with the listener
            walker = ParseTreeWalker()
            walker.walk(listener, tree)
            self.field_list = listener.field_list

            print("Validation completed successfully.")


def extract_error_field(exc: Union[eql.EqlParseError, kql.KqlParseError]) -> Optional[str]:
    """Extract the field name from an EQL or KQL parse error."""
    lines = exc.source.splitlines()
    mod = -1 if exc.line == len(lines) else 0
    line = lines[exc.line + mod]
    start = exc.column
    stop = start + len(exc.caret.strip())
    return line[start:stop]
