# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ES|QL abstract syntax tree (piped command pipeline)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterator

__all__ = (
    "BaseNode",
    "Expression",
    "EsqlQuery",
    "Command",
    "SourceCommand",
    "ProcessingCommand",
    "FromCommand",
    "RowCommand",
    "WhereCommand",
    "KeepCommand",
    "DropCommand",
    "EvalCommand",
    "StatsCommand",
    "SortCommand",
    "LimitCommand",
    "RenameCommand",
    "GrokCommand",
    "DissectCommand",
    "EnrichCommand",
    "MvExpandCommand",
    "JoinCommand",
    "ForkCommand",
    "CompletionCommand",
    "GenericCommand",
    "SetCommand",
    "ShowCommand",
    "PromqlCommand",
    "ExplainCommand",
    "ExternalCommand",
    "SampleCommand",
    "ChangePointCommand",
    "RerankCommand",
    "FuseCommand",
    "AssignFieldCommand",
    "LookupCommand",
    "HighlightCommand",
    "MmrCommand",
    "MetricsInfoCommand",
    "TsInfoCommand",
    "TsCollapseCommand",
    "DedupCommand",
    "ColumnRef",
    "Literal",
    "BinaryExpr",
    "FunctionCall",
    "Wildcard",
    "Alias",
    "NestedQuery",
    "Locus",
)


@dataclass(frozen=True)
class Locus:
    line: int | None = None
    column: int | None = None


class BaseNode:
    """Base AST node with depth-first child iteration."""

    def __init__(self, line: int | None = None, column: int | None = None) -> None:
        self.line = line
        self.column = column

    def iter_children(self) -> Iterator[BaseNode]:
        return iter(())

    def __iter__(self) -> Iterator[BaseNode]:
        yield self
        for child in self.iter_children():
            if isinstance(child, BaseNode):
                yield from child
            elif isinstance(child, (list, tuple)):
                for item in child:
                    if isinstance(item, BaseNode):
                        yield from item

    @property
    def locus(self) -> Locus:
        return Locus(self.line, self.column)


class Expression(BaseNode):
    """Base class for expression nodes."""


class ColumnRef(Expression):
    def __init__(self, name: str, line: int | None = None, column: int | None = None) -> None:
        super().__init__(line, column)
        self.name = name

    def __str__(self) -> str:
        return self.name


class Literal(Expression):
    def __init__(
        self,
        value: Any,
        kind: str | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.value = value
        self.kind = kind


class Wildcard(Expression):
    def __init__(self, pattern: str, line: int | None = None, column: int | None = None) -> None:
        super().__init__(line, column)
        self.pattern = pattern


class Alias(Expression):
    def __init__(self, name: str, expr: Expression, line: int | None = None, column: int | None = None) -> None:
        super().__init__(line, column)
        self.name = name
        self.expr = expr

    def iter_children(self) -> Iterator[BaseNode]:
        yield self.expr


class BinaryExpr(Expression):
    def __init__(
        self,
        op: str,
        left: Expression,
        right: Expression,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.op = op
        self.left = left
        self.right = right

    def iter_children(self) -> Iterator[BaseNode]:
        yield self.left
        yield self.right


class NestedQuery(Expression):
    """Nested query payload (KQL/EQL validated; subquery/PROMQL opaque)."""

    def __init__(
        self,
        kind: str,
        text: str,
        locus: Locus | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        if locus is not None:
            line = line if line is not None else locus.line
            column = column if column is not None else locus.column
        super().__init__(line, column)
        self.kind = kind
        self.text = text


class FunctionCall(Expression):
    def __init__(
        self,
        name: str,
        args: list[Expression] | None = None,
        nested_query: NestedQuery | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.name = name
        self.args = args or []
        self.nested_query = nested_query

    def iter_children(self) -> Iterator[BaseNode]:
        yield from self.args
        if self.nested_query is not None:
            yield self.nested_query


class Command(BaseNode):
    """Base piped command."""


class SourceCommand(Command):
    """Root / source command."""


class ProcessingCommand(Command):
    """Pipeline processing command."""


class FromCommand(SourceCommand):
    def __init__(
        self,
        sources: list[str] | None = None,
        metadata: list[str] | None = None,
        kind: str = "from",
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.sources = sources or []
        self.metadata = metadata or []
        self.kind = kind  # "from" | "ts"


class RowCommand(SourceCommand):
    def __init__(
        self,
        fields: list[Alias] | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.fields = fields or []

    def iter_children(self) -> Iterator[BaseNode]:
        yield from self.fields


class SetCommand(Command):
    """SET preamble (attached to `EsqlQuery.settings`, not the pipe)."""

    def __init__(
        self,
        name: str,
        value: Expression | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.name = name
        self.value = value

    def iter_children(self) -> Iterator[BaseNode]:
        if self.value is not None:
            yield self.value


class ShowCommand(SourceCommand):
    def __init__(
        self,
        info: bool = True,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.info = info


class PromqlCommand(SourceCommand):
    """PROMQL source command — query text is opaque (no nested PromQL validation)."""

    def __init__(
        self,
        query_text: str = "",
        value_name: str | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.query_text = query_text
        self.value_name = value_name


class ExplainCommand(SourceCommand):
    def __init__(
        self,
        query: EsqlQuery | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.query = query

    def iter_children(self) -> Iterator[BaseNode]:
        if self.query is not None:
            yield self.query


class ExternalCommand(SourceCommand):
    def __init__(
        self,
        source: str | None = None,
        text: str = "",
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.source = source
        self.text = text


class WhereCommand(ProcessingCommand):
    def __init__(
        self,
        predicate: Expression | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.predicate = predicate

    def iter_children(self) -> Iterator[BaseNode]:
        if self.predicate is not None:
            yield self.predicate


class KeepCommand(ProcessingCommand):
    def __init__(
        self,
        columns: list[str] | None = None,
        wildcards: list[str] | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.columns = columns or []
        self.wildcards = wildcards or []


class DropCommand(ProcessingCommand):
    def __init__(
        self,
        columns: list[str] | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.columns = columns or []


class EvalCommand(ProcessingCommand):
    def __init__(
        self,
        assignments: list[Alias] | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.assignments = assignments or []

    def iter_children(self) -> Iterator[BaseNode]:
        yield from self.assignments


class StatsCommand(ProcessingCommand):
    """STATS/INLINE STATS.

    ``grouping`` keeps all BY column names in source order. Aliased or
    expression groupings (``BY b = BUCKET(...)``) live in ``grouping_aliases``
    (name + expression); raw field references (``BY host.name``) live in
    ``grouping_refs`` so the analyzer can schema-check them.
    """

    def __init__(
        self,
        aggregates: list[Alias] | None = None,
        grouping: list[str] | None = None,
        inline: bool = False,
        grouping_aliases: list[Alias] | None = None,
        grouping_refs: list[ColumnRef] | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.aggregates = aggregates or []
        self.grouping_aliases = grouping_aliases or []
        self.grouping_refs = grouping_refs or []
        if grouping is None and (self.grouping_aliases or self.grouping_refs):
            grouping = [a.name for a in self.grouping_aliases] + [r.name for r in self.grouping_refs]
        self.grouping = grouping or []
        self.inline = inline

    def iter_children(self) -> Iterator[BaseNode]:
        yield from self.aggregates
        yield from self.grouping_aliases
        yield from self.grouping_refs


class SortCommand(ProcessingCommand):
    def __init__(
        self,
        keys: list[Alias] | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.keys = keys or []

    def iter_children(self) -> Iterator[BaseNode]:
        yield from self.keys


class LimitCommand(ProcessingCommand):
    def __init__(
        self,
        count: int | Expression | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.count = count

    def iter_children(self) -> Iterator[BaseNode]:
        if isinstance(self.count, BaseNode):
            yield self.count


class RenameCommand(ProcessingCommand):
    def __init__(
        self,
        renames: list[tuple[str, str]] | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.renames = renames or []


class GrokCommand(ProcessingCommand):
    def __init__(
        self,
        input_field: str | None = None,
        pattern: str | None = None,
        outputs: list[str] | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.input_field = input_field
        self.pattern = pattern
        self.outputs = outputs or []


class DissectCommand(ProcessingCommand):
    def __init__(
        self,
        input_field: str | None = None,
        pattern: str | None = None,
        outputs: list[str] | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.input_field = input_field
        self.pattern = pattern
        self.outputs = outputs or []


class EnrichCommand(ProcessingCommand):
    def __init__(
        self,
        policy: str | None = None,
        match_field: str | None = None,
        outputs: list[str] | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.policy = policy
        self.match_field = match_field
        self.outputs = outputs or []


class MvExpandCommand(ProcessingCommand):
    def __init__(
        self,
        field: str | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.field = field


class JoinCommand(ProcessingCommand):
    def __init__(
        self,
        kind: str | None = None,
        target: str | None = None,
        on_fields: list[str] | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.kind = kind
        self.target = target
        self.on_fields = on_fields or []


class ForkCommand(ProcessingCommand):
    def __init__(
        self,
        branches: list[EsqlQuery] | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.branches = branches or []

    def iter_children(self) -> Iterator[BaseNode]:
        yield from self.branches


class CompletionCommand(ProcessingCommand):
    def __init__(
        self,
        target_field: str | None = None,
        prompt: Expression | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.target_field = target_field
        self.prompt = prompt

    def iter_children(self) -> Iterator[BaseNode]:
        if self.prompt is not None:
            yield self.prompt


class SampleCommand(ProcessingCommand):
    def __init__(
        self,
        probability: Expression | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.probability = probability

    def iter_children(self) -> Iterator[BaseNode]:
        if self.probability is not None:
            yield self.probability


class ChangePointCommand(ProcessingCommand):
    def __init__(
        self,
        value: str | None = None,
        key: str | None = None,
        target_type: str | None = None,
        target_pvalue: str | None = None,
        groupings: list[Expression] | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.value = value
        self.key = key
        self.target_type = target_type
        self.target_pvalue = target_pvalue
        self.groupings = groupings or []

    def iter_children(self) -> Iterator[BaseNode]:
        yield from self.groupings


class RerankCommand(ProcessingCommand):
    def __init__(
        self,
        target_field: str | None = None,
        query_text: Expression | None = None,
        fields: list[Alias] | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.target_field = target_field
        self.query_text = query_text
        self.fields = fields or []

    def iter_children(self) -> Iterator[BaseNode]:
        if self.query_text is not None:
            yield self.query_text
        yield from self.fields


class FuseCommand(ProcessingCommand):
    def __init__(
        self,
        fuse_type: str | None = None,
        text: str = "",
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.fuse_type = fuse_type
        self.text = text


class AssignFieldCommand(ProcessingCommand):
    """URI_PARTS / REGISTERED_DOMAIN / USER_AGENT / IP_LOCATION."""

    def __init__(
        self,
        command: str,
        target: str = "",
        source: Expression | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.command = command
        self.target = target
        self.source = source

    def iter_children(self) -> Iterator[BaseNode]:
        if self.source is not None:
            yield self.source


class LookupCommand(ProcessingCommand):
    def __init__(
        self,
        table: str | None = None,
        match_fields: list[str] | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.table = table
        self.match_fields = match_fields or []


class HighlightCommand(ProcessingCommand):
    def __init__(
        self,
        query: Expression | None = None,
        fields: list[str] | None = None,
        text: str = "",
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.query = query
        self.fields = fields or []
        self.text = text

    def iter_children(self) -> Iterator[BaseNode]:
        if self.query is not None:
            yield self.query


class MmrCommand(ProcessingCommand):
    def __init__(
        self,
        diversify_field: str | None = None,
        text: str = "",
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.diversify_field = diversify_field
        self.text = text


class MetricsInfoCommand(ProcessingCommand):
    pass


class TsInfoCommand(ProcessingCommand):
    pass


class TsCollapseCommand(ProcessingCommand):
    pass


class DedupCommand(ProcessingCommand):
    pass


class GenericCommand(ProcessingCommand):
    def __init__(
        self,
        name: str = "",
        text: str = "",
        outputs: list[str] | None = None,
        expressions: list[Expression] | None = None,
        nested: EsqlQuery | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.name = name
        self.text = text
        self.outputs = outputs or []
        self.expressions = expressions or []
        self.nested = nested

    def iter_children(self) -> Iterator[BaseNode]:
        yield from self.expressions
        if self.nested is not None:
            yield self.nested


class EsqlQuery(BaseNode):
    def __init__(
        self,
        commands: list[Command] | None = None,
        settings: list[SetCommand] | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(line, column)
        self.commands = commands or []
        self.settings = settings or []

    def iter_children(self) -> Iterator[BaseNode]:
        yield from self.settings
        yield from self.commands

    @property
    def source(self) -> SourceCommand | None:
        for cmd in self.commands:
            if isinstance(cmd, SourceCommand):
                return cmd
        return None
