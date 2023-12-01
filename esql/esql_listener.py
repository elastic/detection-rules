# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
from antlr4 import ParserRuleContext
from antlr4.error.ErrorListener import ErrorListener

from esql.errors import ESQLSemanticError
from esql.EsqlBaseParser import EsqlBaseParser
from esql.EsqlBaseParserListener import EsqlBaseParserListener
from esql.utils import get_node


class ESQLErrorListener(ErrorListener):
    def __init__(self):
        super().__init__()
        self.errors = []

    def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):  # noqa: N802,N803
        self.errors.append(f"Line {line}:{column} {msg}")


class ESQLValidatorListener(EsqlBaseParserListener):
    """Validate specific fields for ESQL query event types."""

    def __init__(self, schema: dict = {}):
        """Initialize the listener with a schema."""
        self.schema = schema  # schema is a dictionary of field names and types
        self.field_list = []  # list of fields used in the query
        self.indices = []  # indices used in the query (e.g. 'logs-*')
        self.event_datasets = []  # event.dataset field values used in the query

    def enterQualifiedName(self, ctx: EsqlBaseParser.QualifiedNameContext):  # noqa: N802
        """Extract field from context (ctx)."""

        # TODO: we need to check if a field can be set in any processing command and ignore these parents
        if (
            not isinstance(ctx.parentCtx, EsqlBaseParser.EvalCommandContext)  # noqa: W503
            and not isinstance(ctx.parentCtx, EsqlBaseParser.MetadataContext)  # noqa: W503
            and not isinstance(  # noqa: W503
                ctx.parentCtx.parentCtx.parentCtx, EsqlBaseParser.StatsCommandContext
            )
        ):
            field = ctx.getText()
            self.field_list.append(field)

            if self.schema and field not in self.schema:
                raise ESQLSemanticError(f"Invalid field: {field}")

    def enterSourceIdentifier(self, ctx: EsqlBaseParser.SourceIdentifierContext):  # noqa: N802
        """Extract index and fields from context (ctx)."""

        # Check if the parent context is NOT 'FromCommandContext'
        if (
            not isinstance(ctx.parentCtx, EsqlBaseParser.FromCommandContext)  # noqa: W503
            and not isinstance(ctx.parentCtx, EsqlBaseParser.MetadataContext)  # noqa: W503
            and not isinstance(  # noqa: W503
                ctx.parentCtx.parentCtx.parentCtx, EsqlBaseParser.StatsCommandContext
            )
        ):
            # Extract field from context (ctx)
            # The implementation depends on your parse tree structure
            # For example, if the field name is directly the text of this context:
            field = ctx.getText()
            self.field_list.append(field)

            if self.schema and field not in self.schema:
                raise ESQLSemanticError(f"Invalid field: {field}")
        else:
            # check index against integrations?
            self.indices.append(ctx.getText())

    def enterSingleStatement(self, ctx: EsqlBaseParser.SingleStatementContext):  # noqa: N802
        """Override entry method for SingleStatementContext."""

        # check if metadata is present for ES|QL queries with no stats command
        metadata_ctx = get_node(ctx, EsqlBaseParser.MetadataContext)
        if not metadata_ctx:
            stats_ctx = get_node(ctx, EsqlBaseParser.StatsCommandContext)
            if not stats_ctx:
                raise ESQLSemanticError("Missing metadata for ES|QL query with no stats command")

    def check_literal_type(self, ctx: ParserRuleContext):
        """Check the type of a literal against the schema."""
        field, context_type = self.find_associated_field_and_context(ctx)

        if field and field in self.schema:
            expected_type = self.schema[field]
            actual_type = self.get_literal_type(ctx, context_type)

            if expected_type != actual_type:
                raise ESQLSemanticError(
                    f"Field '{field}' in context '{context_type}'"
                    f"expects type '{expected_type}', but got '{actual_type}'"
                )

    def find_associated_field_and_context(self, ctx: ParserRuleContext):
        """Find the field and context type associated with a literal."""
        parent_ctx = ctx.parentCtx
        while parent_ctx:
            if isinstance(parent_ctx, EsqlBaseParser.ComparisonContext):
                field_ctx = parent_ctx.operatorExpression(0).getChild(0)
                field = field_ctx.getText() if field_ctx else None
                return field, "Comparison"
            elif isinstance(parent_ctx, EsqlBaseParser.LogicalInContext):
                field_ctx = parent_ctx.valueExpression(0).getChild(0)
                return field_ctx.getText() if field_ctx else None, "LogicalIn"
            # Add additional conditions for other contexts where constants appear
            parent_ctx = parent_ctx.parentCtx
        return None, None

    def get_literal_type(self, ctx: ParserRuleContext, context_type: str):
        """Get the type of a literal."""
        # Determine the type of the literal based on the context type
        # https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html
        if context_type in ["Comparison", "LogicalIn"]:
            if isinstance(ctx, EsqlBaseParser.StringLiteralContext):
                return "keyword"  # or 'text'?, depending on usage
            elif isinstance(ctx, EsqlBaseParser.IntegerLiteralContext):
                return "integer"
            elif isinstance(ctx, EsqlBaseParser.QualifiedIntegerLiteralContext):
                return "long"  # Assuming qualified integers are longs
            elif isinstance(ctx, EsqlBaseParser.DecimalLiteralContext):
                return "double"
            elif isinstance(ctx, EsqlBaseParser.BooleanLiteralContext):
                return "boolean"
            elif isinstance(ctx, EsqlBaseParser.NullLiteralContext):
                return "null"  # 'null' type for missing or null values
            elif (
                isinstance(ctx, EsqlBaseParser.NumericArrayLiteralContext)
                or isinstance(ctx, EsqlBaseParser.StringArrayLiteralContext)  # noqa: W503
                or isinstance(ctx, EsqlBaseParser.BooleanArrayLiteralContext)  # noqa: W503
            ):
                return "nested"  # Array of integers, text, or booleans
        else:
            # Unsupported ECS types in the grammar:
            #     match_only_text
            #     constant_keyword
            #     unsigned_long
            #     binary
            #     histogram
            #     scaled_float
            #     half_float
            #     text
            #     alias
            #     array
            #     float
            #     wildcard
            #     short
            #     ip
            #     object
            #     flattened
            #     byte
            #     geo_point
            #     date
            return "unknown"

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

    def enterBooleanDefault(self, ctx: EsqlBaseParser.BooleanDefaultContext):  # noqa: N802
        """Check the type of a boolean default context against the schema."""
        self.check_literal_type(ctx)

        # extract event datasets
        value = ctx.getText()
        if "event.dataset" in value:
            string_nodes = get_node(ctx, EsqlBaseParser.StringLiteralContext)
            for node in string_nodes:
                self.event_datasets.append(node.getText().strip('"'))
