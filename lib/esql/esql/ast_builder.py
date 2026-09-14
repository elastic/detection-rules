# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Build ES|QL AST nodes from ANTLR parse trees."""

from __future__ import annotations

import re
from typing import Any

from antlr4 import ParseTreeVisitor

from . import ast
from .functions import NESTED_QUERY_FUNCTIONS

__all__ = ("AstBuilder", "build_ast")

# GROK: %{SYNTAX}, %{SYNTAX:SEMANTIC}, %{SYNTAX:SEMANTIC:TYPE}
_GROK_FIELD_RE = re.compile(r"%\{[^:}]+(?::([^:}]+))?(?::[^}]+)?\}")
# Oniguruma / ES GROK also allow named capture groups: (?<name>...) or (?P<name>...)
_GROK_NAMED_GROUP_RE = re.compile(r"\(\?<([A-Za-z_][A-Za-z0-9_]*)>|\(\?P<([A-Za-z_][A-Za-z0-9_]*)>")
# DISSECT: %{field}, %{+field}, %{*field}, %{?field}, %{->skip}
_DISSECT_FIELD_RE = re.compile(r"%\{([^}]+)\}")
_DISSECT_MODIFIER_RE = re.compile(r"^(?:\+\+|\+|\*|\?|->)+")


def _line_col(ctx: Any) -> tuple[int | None, int | None]:
    if ctx is None or ctx.start is None:
        return None, None
    return ctx.start.line - 1, ctx.start.column


def _text(node: Any) -> str:
    if node is None:
        return ""
    # ANTLR TerminalNode
    if hasattr(node, "getSymbol"):
        symbol = node.getSymbol()
        if symbol is not None and getattr(symbol, "text", None) is not None:
            return str(symbol.text)
    # ANTLR Token (labeled operator=…) — must not use str(token)
    text = getattr(node, "text", None)
    if isinstance(text, str) and not hasattr(node, "getChildCount"):
        return text
    if hasattr(node, "getText"):
        return node.getText()
    return str(node)


def _strip_quotes(value: str) -> str:
    if len(value) >= 6 and value[:3] == value[-3:] and value[:3] in ('"""', "'''"):
        return value[3:-3]
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'`":
        return value[1:-1]
    return value


class AstBuilder(ParseTreeVisitor):
    """Visitor that converts ANTLR contexts into `esql.ast` nodes.

    Version-agnostic: does not inherit a generated `EsqlBaseParserVisitor` so the
    same builder works across grammar snapshots (8.19 / 9.3 / 9.4 / 9.5 / latest).
    """

    def visitStatements(self, ctx: Any) -> ast.EsqlQuery:
        settings: list[ast.SetCommand] = []
        for set_ctx in getattr(ctx, "setCommand", lambda: [])() or []:
            result = self.visit(set_ctx)
            if isinstance(result, ast.SetCommand):
                settings.append(result)
        stmt = getattr(ctx, "singleStatement", lambda: None)()
        query = self.visit(stmt) if stmt is not None else ast.EsqlQuery()
        if not isinstance(query, ast.EsqlQuery):
            if isinstance(query, ast.Command):
                query = ast.EsqlQuery(commands=[query])
            else:
                query = ast.EsqlQuery()
        query.settings = settings
        return query

    def visitSingleStatement(self, ctx: Any) -> ast.EsqlQuery:
        line, col = _line_col(ctx)
        query_ctx = ctx.query()
        result = self.visit(query_ctx)
        if isinstance(result, ast.EsqlQuery):
            result.line = line
            result.column = col
            return result
        if isinstance(result, ast.Command):
            return ast.EsqlQuery(commands=[result], line=line, column=col)
        return ast.EsqlQuery(line=line, column=col)

    def visitCompositeQuery(self, ctx: Any) -> ast.EsqlQuery:
        left = self.visit(ctx.query())
        proc = self.visit(ctx.processingCommand())
        if not isinstance(left, ast.EsqlQuery):
            left = ast.EsqlQuery(commands=[left] if isinstance(left, ast.Command) else [])
        if isinstance(proc, ast.Command):
            left.commands.append(proc)
        return left

    def visitSingleCommandQuery(self, ctx: Any) -> ast.EsqlQuery:
        cmd = self.visit(ctx.sourceCommand())
        if isinstance(cmd, ast.Command):
            return ast.EsqlQuery(commands=[cmd])
        return ast.EsqlQuery()

    def visitSourceCommand(self, ctx: Any) -> ast.Command | None:
        for child in ctx.getChildren():
            result = self.visit(child)
            if isinstance(result, ast.Command):
                return result
        return None

    def visitProcessingCommand(self, ctx: Any) -> ast.Command | None:
        for child in ctx.getChildren():
            result = self.visit(child)
            if isinstance(result, ast.Command):
                return result
        raw = _text(ctx).lstrip()
        if raw.startswith("|"):
            raw = raw[1:].lstrip()
        name = raw.split(None, 1)[0].lower() if raw else "unknown"
        # Strip punctuation from command token (e.g. trailing parentheses)
        name = "".join(ch for ch in name if ch.isalnum() or ch == "_") or "unknown"
        return ast.GenericCommand(name=name, text=_text(ctx), line=_line_col(ctx)[0], column=_line_col(ctx)[1])

    def visitFromCommand(self, ctx: Any) -> ast.FromCommand:
        line, col = _line_col(ctx)
        sources, metadata = self._extract_from_sources_and_metadata(ctx)
        return ast.FromCommand(sources=sources, metadata=metadata, kind="from", line=line, column=col)

    def visitTimeSeriesCommand(self, ctx: Any) -> ast.FromCommand:
        line, col = _line_col(ctx)
        sources, metadata = self._extract_from_sources_and_metadata(ctx)
        return ast.FromCommand(sources=sources, metadata=metadata, kind="ts", line=line, column=col)

    def _extract_from_sources_and_metadata(self, ctx: Any) -> tuple[list[str], list[str]]:
        """Support both 8.19 (flat indexPattern*) and 9.3+ (indexPatternAndMetadataFields)."""
        sources: list[str] = []
        metadata: list[str] = []

        # 9.3+ wrapped form
        idx = getattr(ctx, "indexPatternAndMetadataFields", lambda: None)()
        if idx is not None:
            for pattern_ctx in getattr(idx, "indexPatternOrSubquery", lambda: [])() or []:
                src = self._visit_index_pattern(pattern_ctx)
                if src:
                    sources.append(src)
            # Some grammars still expose indexPattern() under the wrapper
            if not sources:
                for pattern_ctx in getattr(idx, "indexPattern", lambda: [])() or []:
                    sources.append(_text(pattern_ctx).strip("`"))
            meta_ctx = getattr(idx, "metadata", lambda: None)()
            metadata.extend(self._extract_metadata_names(meta_ctx))
            return sources, metadata

        # 8.19 flat form: FROM indexPattern (COMMA indexPattern)* metadata?
        for pattern_ctx in getattr(ctx, "indexPattern", lambda: [])() or []:
            sources.append(_text(pattern_ctx).strip("`"))
        metadata.extend(self._extract_metadata_names(getattr(ctx, "metadata", lambda: None)()))
        return sources, metadata

    def _extract_metadata_names(self, meta_ctx: Any) -> list[str]:
        if meta_ctx is None:
            return []
        names: list[str] = []
        # Prefer UNQUOTED_SOURCE tokens when present
        tokens = getattr(meta_ctx, "UNQUOTED_SOURCE", lambda: None)()
        if tokens:
            for token in tokens or []:
                names.append(token.getText())
            return names
        # Fall back to walking nested metadataOption / identifiers
        option = getattr(meta_ctx, "metadataOption", lambda: None)()
        if option is not None:
            tokens = getattr(option, "UNQUOTED_SOURCE", lambda: None)()
            if tokens:
                for token in tokens or []:
                    names.append(token.getText())
                return names
        # Last resort: split raw text after METADATA keyword
        raw = _text(meta_ctx)
        if raw.upper().startswith("METADATA"):
            raw = raw[8:]
        for part in raw.replace("[", " ").replace("]", " ").split(","):
            part = part.strip().strip("`")
            if part and part.upper() != "METADATA":
                names.append(part)
        return names

    def visitRowCommand(self, ctx: Any) -> ast.RowCommand:
        line, col = _line_col(ctx)
        fields_ctx = ctx.fields()
        aliases: list[ast.Alias] = []
        if fields_ctx is not None:
            for field_ctx in fields_ctx.field() or []:
                alias = self._visit_field_alias(field_ctx)
                if alias is not None:
                    aliases.append(alias)
        return ast.RowCommand(fields=aliases, line=line, column=col)

    def visitWhereCommand(self, ctx: Any) -> ast.WhereCommand:
        line, col = _line_col(ctx)
        predicate = None
        expr_ctx = ctx.booleanExpression()
        if expr_ctx is not None:
            predicate = self.visit(expr_ctx)
        return ast.WhereCommand(predicate=predicate, line=line, column=col)

    def visitKeepCommand(self, ctx: Any) -> ast.KeepCommand:
        line, col = _line_col(ctx)
        columns, wildcards = self._visit_name_patterns(ctx.qualifiedNamePatterns())
        return ast.KeepCommand(columns=columns, wildcards=wildcards, line=line, column=col)

    def visitDropCommand(self, ctx: Any) -> ast.DropCommand:
        line, col = _line_col(ctx)
        columns, _ = self._visit_name_patterns(ctx.qualifiedNamePatterns())
        return ast.DropCommand(columns=columns, line=line, column=col)

    def visitEvalCommand(self, ctx: Any) -> ast.EvalCommand:
        line, col = _line_col(ctx)
        assignments: list[ast.Alias] = []
        fields_ctx = ctx.fields()
        if fields_ctx is not None:
            for field_ctx in fields_ctx.field() or []:
                alias = self._visit_field_alias(field_ctx)
                if alias is not None:
                    assignments.append(alias)
        return ast.EvalCommand(assignments=assignments, line=line, column=col)

    def visitStatsCommand(self, ctx: Any) -> ast.StatsCommand:
        line, col = _line_col(ctx)
        aggregates: list[ast.Alias] = []
        grouping: list[str] = []
        grouping_aliases: list[ast.Alias] = []
        grouping_refs: list[ast.ColumnRef] = []
        stats_ctx = ctx.aggFields()
        if stats_ctx is not None:
            for agg_ctx in stats_ctx.aggField() or []:
                field_ctx = agg_ctx.field()
                if field_ctx is not None:
                    alias = self._visit_field_alias(field_ctx)
                    if alias is not None:
                        aggregates.append(alias)
        group_ctx = ctx.fields()
        if group_ctx is not None:
            for field_ctx in group_ctx.field() or []:
                gline, gcol = _line_col(field_ctx)
                expr = None
                if field_ctx.booleanExpression() is not None:
                    expr = self.visit(field_ctx.booleanExpression())
                if (
                    field_ctx.ASSIGN() is not None
                    and field_ctx.qualifiedName() is not None
                    and isinstance(expr, ast.Expression)
                ):
                    name = self._visit_qualified_name(field_ctx.qualifiedName())
                    if name:
                        grouping.append(name)
                        grouping_aliases.append(ast.Alias(name=name, expr=expr, line=gline, column=gcol))
                        continue
                if isinstance(expr, ast.ColumnRef):
                    grouping.append(expr.name)
                    grouping_refs.append(expr)
                elif isinstance(expr, ast.Expression):
                    # Unaliased grouping expression — the engine names the
                    # output column after the expression text.
                    name = self._visit_qualified_field(field_ctx) or _text(field_ctx)
                    if name:
                        grouping.append(name)
                        grouping_aliases.append(ast.Alias(name=name, expr=expr, line=gline, column=gcol))
                else:
                    name = self._visit_qualified_field(field_ctx)
                    if name:
                        grouping.append(name)
                        grouping_refs.append(ast.ColumnRef(name=name, line=gline, column=gcol))
        return ast.StatsCommand(
            aggregates=aggregates,
            grouping=grouping,
            inline=False,
            grouping_aliases=grouping_aliases,
            grouping_refs=grouping_refs,
            line=line,
            column=col,
        )

    def visitSortCommand(self, ctx: Any) -> ast.SortCommand:
        line, col = _line_col(ctx)
        keys: list[ast.Alias] = []
        # Grammar: SORT orderExpression (COMMA orderExpression)*
        for order_ctx in ctx.orderExpression() or []:
            bool_ctx = order_ctx.booleanExpression() if hasattr(order_ctx, "booleanExpression") else None
            expr = self.visit(bool_ctx) if bool_ctx is not None else None
            if not isinstance(expr, ast.Expression):
                expr = ast.ColumnRef(name=_text(order_ctx), line=line, column=col)
            name = getattr(expr, "name", None) or _text(order_ctx)
            keys.append(ast.Alias(name=str(name), expr=expr, line=line, column=col))
        return ast.SortCommand(keys=keys, line=line, column=col)

    def visitLimitCommand(self, ctx: Any) -> ast.LimitCommand:
        line, col = _line_col(ctx)
        count: ast.Expression | int | None = None
        for child in ctx.getChildren():
            text = _text(child)
            if text.isdigit():
                count = int(text)
        return ast.LimitCommand(count=count, line=line, column=col)

    def visitRenameCommand(self, ctx: Any) -> ast.RenameCommand:
        line, col = _line_col(ctx)
        renames: list[tuple[str, str]] = []
        for clause in ctx.renameClause() or []:
            patterns = clause.qualifiedNamePattern() or []
            old_ctx = getattr(clause, "oldName", None) or (patterns[0] if patterns else None)
            new_ctx = getattr(clause, "newName", None) or (patterns[1] if len(patterns) > 1 else None)
            old_name = _text(old_ctx).replace("`", "") if old_ctx is not None else ""
            new_name = _text(new_ctx).replace("`", "") if new_ctx is not None else ""
            if old_name and new_name:
                renames.append((old_name, new_name))
        return ast.RenameCommand(renames=renames, line=line, column=col)

    def visitGrokCommand(self, ctx: Any) -> ast.GrokCommand:
        line, col = _line_col(ctx)
        input_field = self._primary_field_name(ctx.primaryExpression())
        patterns = [_strip_quotes(_text(s)) for s in _as_list(ctx.string())]
        pattern = patterns[0] if patterns else None
        outputs: list[str] = []
        for pat in patterns:
            outputs.extend(_grok_output_fields(pat))
        return ast.GrokCommand(
            input_field=input_field,
            pattern=pattern,
            outputs=outputs,
            line=line,
            column=col,
        )

    def visitDissectCommand(self, ctx: Any) -> ast.DissectCommand:
        line, col = _line_col(ctx)
        input_field = self._primary_field_name(ctx.primaryExpression())
        string_ctxs = _as_list(ctx.string())
        pattern = _strip_quotes(_text(string_ctxs[0])) if string_ctxs else None
        outputs = _dissect_output_fields(pattern or "")
        return ast.DissectCommand(
            input_field=input_field,
            pattern=pattern,
            outputs=outputs,
            line=line,
            column=col,
        )

    def visitEnrichCommand(self, ctx: Any) -> ast.EnrichCommand:
        line, col = _line_col(ctx)
        policy = None
        policy_ctx = ctx.enrichPolicyName() if hasattr(ctx, "enrichPolicyName") else None
        if policy_ctx is not None:
            policy = _text(policy_ctx)
        match_field = None
        qnp = ctx.qualifiedNamePattern() if hasattr(ctx, "qualifiedNamePattern") else None
        if qnp is not None:
            # ON <field> — single pattern when present
            match_field = _text(qnp) if not isinstance(qnp, list) else (_text(qnp[0]) if qnp else None)
        outputs: list[str] = []
        with_clauses = ctx.enrichWithClause() if hasattr(ctx, "enrichWithClause") else None
        if with_clauses is not None:
            clauses = with_clauses if isinstance(with_clauses, list) else [with_clauses]
            for clause in clauses:
                patterns = clause.qualifiedNamePattern() if hasattr(clause, "qualifiedNamePattern") else None
                if patterns is None:
                    continue
                for pattern in patterns if isinstance(patterns, list) else [patterns]:
                    name = _text(pattern)
                    if name:
                        outputs.append(name)
        return ast.EnrichCommand(policy=policy, match_field=match_field, outputs=outputs, line=line, column=col)

    def visitInlineStatsCommand(self, ctx: Any) -> ast.StatsCommand:
        """INLINE STATS shares StatsCommand shape for defined-column tracking."""
        cmd = self.visitStatsCommand(ctx)
        cmd.inline = True
        return cmd

    def visitInlinestatsCommand(self, ctx: Any) -> ast.StatsCommand:
        # 8.19 grammar uses InlinestatsCommand (lowercase 's').
        cmd = self.visitStatsCommand(ctx)
        cmd.inline = True
        return cmd

    def visitMvExpandCommand(self, ctx: Any) -> ast.MvExpandCommand:
        line, col = _line_col(ctx)
        field = None
        qn = ctx.qualifiedName()
        if qn is not None:
            field = self._visit_qualified_name(qn)
        return ast.MvExpandCommand(field=field, line=line, column=col)

    def visitJoinCommand(self, ctx: Any) -> ast.JoinCommand:
        line, col = _line_col(ctx)
        kind = None
        if hasattr(ctx, "JOIN_LOOKUP") and ctx.JOIN_LOOKUP() is not None:
            kind = "lookup"
        elif hasattr(ctx, "DEV_JOIN_LEFT") and ctx.DEV_JOIN_LEFT() is not None:
            kind = "left"
        elif hasattr(ctx, "DEV_JOIN_RIGHT") and ctx.DEV_JOIN_RIGHT() is not None:
            kind = "right"
        elif hasattr(ctx, "JOIN") and ctx.JOIN() is not None:
            kind = "join"
        target = None
        target_ctx = ctx.joinTarget() if hasattr(ctx, "joinTarget") else None
        if target_ctx is not None:
            index_pattern = target_ctx.indexPattern() if hasattr(target_ctx, "indexPattern") else None
            target = _text(index_pattern) if index_pattern is not None else _text(target_ctx)
        on_fields: list[str] = []
        cond = ctx.joinCondition() if hasattr(ctx, "joinCondition") else None
        if cond is not None:
            bool_exprs = cond.booleanExpression() if hasattr(cond, "booleanExpression") else None
            if bool_exprs is not None:
                for expr_ctx in bool_exprs if isinstance(bool_exprs, list) else [bool_exprs]:
                    name = _text(expr_ctx)
                    if name:
                        on_fields.append(name)
        return ast.JoinCommand(kind=kind, target=target, on_fields=on_fields, line=line, column=col)

    def visitForkCommand(self, ctx: Any) -> ast.ForkCommand:
        line, col = _line_col(ctx)
        branches: list[ast.EsqlQuery] = []
        sub = getattr(ctx, "forkSubQueries", lambda: None)()
        if sub is not None:
            result = self.visit(sub)
            if isinstance(result, list):
                branches = [b for b in result if isinstance(b, ast.EsqlQuery)]
        return ast.ForkCommand(branches=branches, line=line, column=col)

    def visitForkSubQueries(self, ctx: Any) -> list[ast.EsqlQuery]:
        branches: list[ast.EsqlQuery] = []
        for sq in getattr(ctx, "forkSubQuery", lambda: [])() or []:
            branch = self.visit(sq)
            if isinstance(branch, ast.EsqlQuery):
                branches.append(branch)
        return branches

    def visitForkSubQuery(self, ctx: Any) -> ast.EsqlQuery:
        cmd_ctx = getattr(ctx, "forkSubQueryCommand", lambda: None)()
        result = self.visit(cmd_ctx) if cmd_ctx is not None else None
        if isinstance(result, ast.EsqlQuery):
            return result
        if isinstance(result, ast.Command):
            return ast.EsqlQuery(commands=[result])
        if isinstance(result, list):
            return ast.EsqlQuery(commands=[c for c in result if isinstance(c, ast.Command)])
        return ast.EsqlQuery()

    def visitSingleForkSubQueryCommand(self, ctx: Any) -> ast.Command | ast.EsqlQuery | None:
        proc = getattr(ctx, "forkSubQueryProcessingCommand", lambda: None)()
        return self.visit(proc) if proc is not None else None

    def visitCompositeForkSubQuery(self, ctx: Any) -> ast.EsqlQuery:
        left = self.visit(getattr(ctx, "forkSubQueryCommand", lambda: None)())
        right = self.visit(getattr(ctx, "forkSubQueryProcessingCommand", lambda: None)())
        cmds: list[ast.Command] = []
        if isinstance(left, ast.EsqlQuery):
            cmds.extend(left.commands)
        elif isinstance(left, ast.Command):
            cmds.append(left)
        elif isinstance(left, list):
            cmds.extend(c for c in left if isinstance(c, ast.Command))
        if isinstance(right, ast.Command):
            cmds.append(right)
        return ast.EsqlQuery(commands=cmds)

    def visitForkSubQueryProcessingCommand(self, ctx: Any) -> ast.Command | None:
        proc = getattr(ctx, "processingCommand", lambda: None)()
        result = self.visit(proc) if proc is not None else None
        return result if isinstance(result, ast.Command) else None

    def visitCompletionCommand(self, ctx: Any) -> ast.CompletionCommand:
        line, col = _line_col(ctx)
        target_field = None
        # Labeled targetField=qualifiedName, or first qualifiedName when ASSIGN present
        target_ctx = getattr(ctx, "targetField", None)
        if target_ctx is None:
            qn = getattr(ctx, "qualifiedName", lambda: None)()
            if qn is not None and getattr(ctx, "ASSIGN", lambda: None)() is not None:
                target_ctx = qn
        if target_ctx is not None:
            target_field = self._visit_qualified_name(target_ctx)
        prompt = None
        prompt_ctx = getattr(ctx, "prompt", None)
        if prompt_ctx is None:
            prompt_ctx = getattr(ctx, "primaryExpression", lambda: None)()
        if prompt_ctx is not None:
            visited = self.visit(prompt_ctx)
            if isinstance(visited, ast.Expression):
                prompt = visited
        return ast.CompletionCommand(target_field=target_field, prompt=prompt, line=line, column=col)

    def visitShowInfo(self, ctx: Any) -> ast.ShowCommand:
        line, col = _line_col(ctx)
        return ast.ShowCommand(info=True, line=line, column=col)

    def visitSetCommand(self, ctx: Any) -> ast.SetCommand:
        line, col = _line_col(ctx)
        field_ctx = getattr(ctx, "setField", lambda: None)()
        if field_ctx is not None:
            result = self.visit(field_ctx)
            if isinstance(result, ast.SetCommand):
                result.line = line
                result.column = col
                return result
        return ast.SetCommand(name="", line=line, column=col)

    def visitSetField(self, ctx: Any) -> ast.SetCommand:
        line, col = _line_col(ctx)
        name = ""
        ident = getattr(ctx, "identifier", lambda: None)()
        if ident is not None:
            name = _text(ident).strip("`")
        value: ast.Expression | None = None
        const_ctx = getattr(ctx, "constant", lambda: None)()
        if const_ctx is not None:
            visited = self.visit(const_ctx)
            if isinstance(visited, ast.Expression):
                value = visited
        else:
            map_ctx = getattr(ctx, "mapExpression", lambda: None)()
            if map_ctx is not None:
                visited = self.visit(map_ctx)
                if isinstance(visited, ast.Expression):
                    value = visited
        return ast.SetCommand(name=name, value=value, line=line, column=col)

    def visitPromqlCommand(self, ctx: Any) -> ast.PromqlCommand:
        line, col = _line_col(ctx)
        value_name = None
        vn = getattr(ctx, "valueName", lambda: None)()
        if vn is not None:
            value_name = _text(vn).strip("`")
        parts = getattr(ctx, "promqlQueryPart", lambda: [])() or []
        if parts:
            part_list = parts if isinstance(parts, list) else [parts]
            query_text = "".join(_text(p) for p in part_list)
        else:
            raw = _text(ctx)
            query_text = raw[6:].strip() if raw.upper().startswith("PROMQL") else raw
        return ast.PromqlCommand(query_text=query_text, value_name=value_name, line=line, column=col)

    def visitExplainCommand(self, ctx: Any) -> ast.ExplainCommand:
        line, col = _line_col(ctx)
        nested: ast.EsqlQuery | None = None
        sub = getattr(ctx, "subqueryExpression", lambda: None)()
        if sub is not None:
            result = self.visit(sub)
            if isinstance(result, ast.EsqlQuery):
                nested = result
        return ast.ExplainCommand(query=nested, line=line, column=col)

    def visitSubqueryExpression(self, ctx: Any) -> ast.EsqlQuery:
        query_ctx = getattr(ctx, "query", lambda: None)()
        result = self.visit(query_ctx) if query_ctx is not None else None
        if isinstance(result, ast.EsqlQuery):
            return result
        if isinstance(result, ast.Command):
            return ast.EsqlQuery(commands=[result])
        return ast.EsqlQuery()

    def visitExternalCommand(self, ctx: Any) -> ast.ExternalCommand:
        line, col = _line_col(ctx)
        source = None
        sop = getattr(ctx, "stringOrParameter", lambda: None)()
        if sop is not None:
            source = _strip_quotes(_text(sop))
        return ast.ExternalCommand(source=source, text=_text(ctx), line=line, column=col)

    def visitSampleCommand(self, ctx: Any) -> ast.SampleCommand:
        line, col = _line_col(ctx)
        probability = None
        # Labeled probability=constant
        prob_ctx = getattr(ctx, "probability", None)
        if prob_ctx is None:
            prob_ctx = getattr(ctx, "constant", lambda: None)()
        if prob_ctx is not None:
            visited = self.visit(prob_ctx)
            if isinstance(visited, ast.Expression):
                probability = visited
        return ast.SampleCommand(probability=probability, line=line, column=col)

    def visitChangePointCommand(self, ctx: Any) -> ast.ChangePointCommand:
        line, col = _line_col(ctx)
        value = None
        value_ctx = getattr(ctx, "value", None)
        if value_ctx is None:
            qnames = getattr(ctx, "qualifiedName", lambda: [])() or []
            value_ctx = qnames[0] if qnames else None
        if value_ctx is not None:
            value = self._visit_qualified_name(value_ctx)
        key = None
        key_ctx = getattr(ctx, "key", None)
        if key_ctx is not None:
            key = self._visit_qualified_name(key_ctx)
        target_type = None
        tt = getattr(ctx, "targetType", None)
        if tt is not None:
            target_type = self._visit_qualified_name(tt)
        target_pvalue = None
        tp = getattr(ctx, "targetPvalue", None)
        if tp is not None:
            target_pvalue = self._visit_qualified_name(tp)
        groupings: list[ast.Expression] = []
        for gctx in getattr(ctx, "groupings", None) or []:
            visited = self.visit(gctx)
            if isinstance(visited, ast.Expression):
                groupings.append(visited)
        return ast.ChangePointCommand(
            value=value,
            key=key,
            target_type=target_type,
            target_pvalue=target_pvalue,
            groupings=groupings,
            line=line,
            column=col,
        )

    def visitRerankCommand(self, ctx: Any) -> ast.RerankCommand:
        line, col = _line_col(ctx)
        target_field = None
        tf = getattr(ctx, "targetField", None)
        if tf is not None:
            target_field = self._visit_qualified_name(tf)
        query_text = None
        qt = getattr(ctx, "queryText", None)
        if qt is None:
            qt = getattr(ctx, "constant", lambda: None)()
        if qt is not None:
            visited = self.visit(qt)
            if isinstance(visited, ast.Expression):
                query_text = visited
        fields: list[ast.Alias] = []
        fields_ctx = getattr(ctx, "rerankFields", None)
        if fields_ctx is None:
            fields_ctx = getattr(ctx, "fields", lambda: None)()
        if fields_ctx is not None:
            for field_ctx in getattr(fields_ctx, "field", lambda: [])() or []:
                alias = self._visit_field_alias(field_ctx)
                if alias is not None:
                    fields.append(alias)
        return ast.RerankCommand(
            target_field=target_field,
            query_text=query_text,
            fields=fields,
            line=line,
            column=col,
        )

    def visitFuseCommand(self, ctx: Any) -> ast.FuseCommand:
        line, col = _line_col(ctx)
        fuse_type = None
        ft = getattr(ctx, "fuseType", None)
        if ft is None:
            ft = getattr(ctx, "identifier", lambda: None)()
        if ft is not None:
            fuse_type = _text(ft).strip("`")
        return ast.FuseCommand(fuse_type=fuse_type, text=_text(ctx), line=line, column=col)

    def visitUriPartsCommand(self, ctx: Any) -> ast.AssignFieldCommand:
        return self._visit_assign_field_command(ctx, "uri_parts")

    def visitRegisteredDomainCommand(self, ctx: Any) -> ast.AssignFieldCommand:
        return self._visit_assign_field_command(ctx, "registered_domain")

    def visitUserAgentCommand(self, ctx: Any) -> ast.AssignFieldCommand:
        return self._visit_assign_field_command(ctx, "user_agent")

    def visitIpLocationCommand(self, ctx: Any) -> ast.AssignFieldCommand:
        return self._visit_assign_field_command(ctx, "ip_location")

    def _visit_assign_field_command(self, ctx: Any, command: str) -> ast.AssignFieldCommand:
        line, col = _line_col(ctx)
        target = ""
        qn = getattr(ctx, "qualifiedName", lambda: None)()
        if qn is not None:
            target = self._visit_qualified_name(qn)
        source = None
        pe = getattr(ctx, "primaryExpression", lambda: None)()
        if pe is not None:
            visited = self.visit(pe)
            if isinstance(visited, ast.Expression):
                source = visited
        return ast.AssignFieldCommand(command=command, target=target, source=source, line=line, column=col)

    def visitLookupCommand(self, ctx: Any) -> ast.LookupCommand:
        line, col = _line_col(ctx)
        table = None
        table_ctx = getattr(ctx, "tableName", None)
        if table_ctx is None:
            table_ctx = getattr(ctx, "indexPattern", lambda: None)()
        if table_ctx is not None:
            table = _text(table_ctx).strip("`")
        match_fields: list[str] = []
        mf = getattr(ctx, "matchFields", None)
        if mf is None:
            mf = getattr(ctx, "qualifiedNamePatterns", lambda: None)()
        if mf is not None:
            cols, wildcards = self._visit_name_patterns(mf)
            match_fields = cols + wildcards
        return ast.LookupCommand(table=table, match_fields=match_fields, line=line, column=col)

    def visitDedupCommand(self, ctx: Any) -> ast.DedupCommand:
        line, col = _line_col(ctx)
        return ast.DedupCommand(line=line, column=col)

    def visitHighlightCommand(self, ctx: Any) -> ast.HighlightCommand:
        line, col = _line_col(ctx)
        query = None
        qe = getattr(ctx, "queryExpression", None)
        if qe is None:
            qe = getattr(ctx, "booleanExpression", lambda: None)()
        if qe is not None:
            visited = self.visit(qe)
            if isinstance(visited, ast.Expression):
                query = visited
        fields: list[str] = []
        hf = getattr(ctx, "highlightFields", None)
        if hf is None:
            hf = getattr(ctx, "qualifiedNames", lambda: None)()
        if hf is not None:
            for qn in getattr(hf, "qualifiedName", lambda: [])() or []:
                name = self._visit_qualified_name(qn)
                if name:
                    fields.append(name)
        return ast.HighlightCommand(query=query, fields=fields, text=_text(ctx), line=line, column=col)

    def visitMmrCommand(self, ctx: Any) -> ast.MmrCommand:
        line, col = _line_col(ctx)
        diversify_field = None
        df = getattr(ctx, "diversifyField", None)
        if df is None:
            df = getattr(ctx, "qualifiedName", lambda: None)()
        if df is not None:
            diversify_field = self._visit_qualified_name(df)
        return ast.MmrCommand(diversify_field=diversify_field, text=_text(ctx), line=line, column=col)

    def visitMetricsInfoCommand(self, ctx: Any) -> ast.MetricsInfoCommand:
        line, col = _line_col(ctx)
        return ast.MetricsInfoCommand(line=line, column=col)

    def visitTsInfoCommand(self, ctx: Any) -> ast.TsInfoCommand:
        line, col = _line_col(ctx)
        return ast.TsInfoCommand(line=line, column=col)

    def visitTsCollapseCommand(self, ctx: Any) -> ast.TsCollapseCommand:
        line, col = _line_col(ctx)
        return ast.TsCollapseCommand(line=line, column=col)

    def visitLogicalInSubquery(self, ctx: Any) -> ast.Expression | None:
        line, col = _line_col(ctx)
        value_ctx = getattr(ctx, "valueExpression", lambda: None)()
        left = self.visit(value_ctx) if value_ctx is not None else None
        sub_ctx = getattr(ctx, "subquery", lambda: None)()
        text = _text(sub_ctx) if sub_ctx is not None else _text(ctx)
        right = ast.NestedQuery(kind="subquery", text=text, line=line, column=col)
        op = "not_in" if getattr(ctx, "NOT", lambda: None)() is not None else "in"
        if isinstance(left, ast.Expression):
            return ast.BinaryExpr(op=op, left=left, right=right, line=line, column=col)
        return None

    def visitMapExpression(self, ctx: Any) -> ast.Expression:
        line, col = _line_col(ctx)
        return ast.Literal(value=_text(ctx), kind="map", line=line, column=col)

    def visitLambda(self, ctx: Any) -> ast.Expression:
        line, col = _line_col(ctx)
        return ast.Literal(value=_text(ctx), kind="lambda", line=line, column=col)

    def visitEntryExpression(self, ctx: Any) -> ast.Expression:
        line, col = _line_col(ctx)
        return ast.Literal(value=_text(ctx), kind="map_entry", line=line, column=col)

    def visitMapValue(self, ctx: Any) -> ast.Expression | None:
        for child in ctx.getChildren():
            result = self.visit(child)
            if isinstance(result, ast.Expression):
                return result
        line, col = _line_col(ctx)
        return ast.Literal(value=_text(ctx), kind="map_value", line=line, column=col)

    def visitBooleanDefault(self, ctx: Any) -> ast.Expression | None:
        ve = ctx.valueExpression()
        return self.visit(ve) if ve is not None else None

    def visitLogicalBinary(self, ctx: Any) -> ast.Expression | None:
        line, col = _line_col(ctx)
        left = self.visit(ctx.left) if ctx.left is not None else None
        right = self.visit(ctx.right) if ctx.right is not None else None
        op = ctx.operator.text.lower() if ctx.operator is not None else "and"
        if isinstance(left, ast.Expression) and isinstance(right, ast.Expression):
            return ast.BinaryExpr(op=op, left=left, right=right, line=line, column=col)
        return left if isinstance(left, ast.Expression) else right

    def visitLogicalNot(self, ctx: Any) -> ast.Expression | None:
        line, col = _line_col(ctx)
        child_ctx = ctx.booleanExpression()
        child = self.visit(child_ctx) if child_ctx is not None else None
        if isinstance(child, ast.Expression):
            return ast.FunctionCall(name="not", args=[child], line=line, column=col)
        return None

    def visitLogicalIn(self, ctx: Any) -> ast.Expression | None:
        line, col = _line_col(ctx)
        value_exprs = ctx.valueExpression() or []
        if not value_exprs:
            return None
        left = self.visit(value_exprs[0])
        values: list[ast.Expression] = []
        for expr_ctx in value_exprs[1:]:
            value = self.visit(expr_ctx)
            if isinstance(value, ast.Expression):
                values.append(value)
        op = "not_in" if ctx.NOT() is not None else "in"
        if isinstance(left, ast.Expression):
            right = ast.FunctionCall(name="__values__", args=values, line=line, column=col)
            return ast.BinaryExpr(op=op, left=left, right=right, line=line, column=col)
        return None

    def visitIsNull(self, ctx: Any) -> ast.Expression | None:
        line, col = _line_col(ctx)
        value_ctx = ctx.valueExpression()
        value = self.visit(value_ctx) if value_ctx is not None else None
        name = "is_not_null" if ctx.NOT() is not None else "is_null"
        if isinstance(value, ast.Expression):
            return ast.FunctionCall(name=name, args=[value], line=line, column=col)
        return None

    def visitRegexExpression(self, ctx: Any) -> ast.Expression | None:
        regex_ctx = ctx.regexBooleanExpression()
        return self.visit(regex_ctx) if regex_ctx is not None else None

    def visitLikeExpression(self, ctx: Any) -> ast.Expression | None:
        return self._visit_like_rlike(ctx, "like")

    def visitRlikeExpression(self, ctx: Any) -> ast.Expression | None:
        return self._visit_like_rlike(ctx, "rlike")

    def visitLikeListExpression(self, ctx: Any) -> ast.Expression | None:
        return self._visit_like_rlike(ctx, "like")

    def visitRlikeListExpression(self, ctx: Any) -> ast.Expression | None:
        return self._visit_like_rlike(ctx, "rlike")

    def visitMatchExpression(self, ctx: Any) -> ast.Expression | None:
        match_ctx = ctx.matchBooleanExpression()
        return self.visit(match_ctx) if match_ctx is not None else None

    def visitMatchBooleanExpression(self, ctx: Any) -> ast.Expression | None:
        line, col = _line_col(ctx)
        field = self.visit(ctx.fieldExp) if ctx.fieldExp is not None else None
        query = self.visit(ctx.matchQuery) if ctx.matchQuery is not None else None
        if isinstance(field, ast.Expression) and isinstance(query, ast.Expression):
            return ast.FunctionCall(name="match", args=[field, query], line=line, column=col)
        return None

    def visitValueExpressionDefault(self, ctx: Any) -> ast.Expression | None:
        oe = ctx.operatorExpression()
        return self.visit(oe) if oe is not None else None

    def visitComparison(self, ctx: Any) -> ast.Expression | None:
        line, col = _line_col(ctx)
        left = self.visit(ctx.left) if ctx.left is not None else None
        right = self.visit(ctx.right) if ctx.right is not None else None
        op_ctx = ctx.comparisonOperator()
        op = _text(op_ctx) if op_ctx is not None else "=="
        if isinstance(left, ast.Expression) and isinstance(right, ast.Expression):
            return ast.BinaryExpr(op=op, left=left, right=right, line=line, column=col)
        return left if isinstance(left, ast.Expression) else right

    def visitOperatorExpressionDefault(self, ctx: Any) -> ast.Expression | None:
        pe = ctx.primaryExpression()
        return self.visit(pe) if pe is not None else None

    def visitArithmeticUnary(self, ctx: Any) -> ast.Expression | None:
        line, col = _line_col(ctx)
        op = _text(ctx.operator) if ctx.operator is not None else "-"
        child_ctx = ctx.operatorExpression()
        child = self.visit(child_ctx) if child_ctx is not None else None
        if not isinstance(child, ast.Expression):
            return None
        if op == "+":
            return child
        return ast.FunctionCall(name=op, args=[child], line=line, column=col)

    def visitArithmeticBinary(self, ctx: Any) -> ast.Expression | None:
        line, col = _line_col(ctx)
        left = self.visit(ctx.left) if ctx.left is not None else None
        right = self.visit(ctx.right) if ctx.right is not None else None
        op = _text(ctx.operator) if ctx.operator is not None else "+"
        if isinstance(left, ast.Expression) and isinstance(right, ast.Expression):
            return ast.BinaryExpr(op=op, left=left, right=right, line=line, column=col)
        return left if isinstance(left, ast.Expression) else right

    def visitConstantDefault(self, ctx: Any) -> ast.Expression | None:
        constant_ctx = ctx.constant()
        return self.visit(constant_ctx) if constant_ctx is not None else None

    def visitDereference(self, ctx: Any) -> ast.Expression | None:
        qn = ctx.qualifiedName()
        return self.visit(qn) if qn is not None else None

    def visitFunction(self, ctx: Any) -> ast.Expression | None:
        fn = ctx.functionExpression()
        return self.visit(fn) if fn is not None else None

    def visitParenthesizedExpression(self, ctx: Any) -> ast.Expression | None:
        be = ctx.booleanExpression()
        return self.visit(be) if be is not None else None

    def visitInlineCast(self, ctx: Any) -> ast.Expression | None:
        pe = ctx.primaryExpression()
        return self.visit(pe) if pe is not None else None

    def visitNullLiteral(self, ctx: Any) -> ast.Literal | None:
        line, col = _line_col(ctx)
        return ast.Literal(value=None, kind="null", line=line, column=col)

    def visitBooleanLiteral(self, ctx: Any) -> ast.Literal | None:
        line, col = _line_col(ctx)
        bool_ctx = ctx.booleanValue()
        text = _text(bool_ctx).lower()
        return ast.Literal(value=text == "true", kind="boolean", line=line, column=col)

    def visitIntegerLiteral(self, ctx: Any) -> ast.Literal | None:
        line, col = _line_col(ctx)
        int_ctx = ctx.integerValue()
        if int_ctx is None:
            return None
        return ast.Literal(value=int(_text(int_ctx)), kind="long", line=line, column=col)

    def visitDecimalLiteral(self, ctx: Any) -> ast.Literal | None:
        line, col = _line_col(ctx)
        dec_ctx = ctx.decimalValue()
        if dec_ctx is None:
            return None
        return ast.Literal(value=float(_text(dec_ctx)), kind="double", line=line, column=col)

    def visitStringLiteral(self, ctx: Any) -> ast.Literal | None:
        line, col = _line_col(ctx)
        string_ctx = ctx.string()
        if string_ctx is None:
            return None
        token = string_ctx.QUOTED_STRING()
        if token is None:
            return None
        return ast.Literal(value=_strip_quotes(token.getText()), kind="string", line=line, column=col)

    def visitQualifiedIntegerLiteral(self, ctx: Any) -> ast.Literal | None:
        line, col = _line_col(ctx)
        int_ctx = ctx.integerValue()
        unit_token = ctx.UNQUOTED_IDENTIFIER()
        unit = unit_token.getText() if unit_token is not None else ""
        if int_ctx is None:
            return None
        return ast.Literal(value=f"{_text(int_ctx)}{unit}", kind="string", line=line, column=col)

    def visitInputParameter(self, ctx: Any) -> ast.Expression | None:
        line, col = _line_col(ctx)
        param_ctx = ctx.parameter()
        if param_ctx is None:
            return None
        return ast.ColumnRef(name=_text(param_ctx), line=line, column=col)

    def visitNumericArrayLiteral(self, ctx: Any) -> ast.Literal | None:
        line, col = _line_col(ctx)
        values: list[int | float] = []
        for numeric_ctx in ctx.numericValue() or []:
            text = _text(numeric_ctx)
            values.append(float(text) if "." in text else int(text))
        return ast.Literal(value=values, kind="numeric_array", line=line, column=col)

    def visitBooleanArrayLiteral(self, ctx: Any) -> ast.Literal | None:
        line, col = _line_col(ctx)
        values = [_text(bool_ctx).lower() == "true" for bool_ctx in ctx.booleanValue() or []]
        return ast.Literal(value=values, kind="boolean_array", line=line, column=col)

    def visitStringArrayLiteral(self, ctx: Any) -> ast.Literal | None:
        line, col = _line_col(ctx)
        values: list[str] = []
        for string_ctx in ctx.string() or []:
            token = string_ctx.QUOTED_STRING()
            if token is not None:
                values.append(_strip_quotes(token.getText()))
        return ast.Literal(value=values, kind="string_array", line=line, column=col)

    def visitFunctionExpression(self, ctx: Any) -> ast.Expression | None:
        line, col = _line_col(ctx)
        name_ctx = ctx.functionName()
        name = _text(name_ctx).lower() if name_ctx else ""
        args: list[ast.Expression] = []
        # main tip: functionParam*; 9.5 and older: booleanExpression*
        param_getter = getattr(ctx, "functionParam", None)
        expr_getter = getattr(ctx, "booleanExpression", None)
        param_ctxs = param_getter() if callable(param_getter) else None
        if param_ctxs:
            for param_ctx in param_ctxs or []:
                arg = self.visit(param_ctx)
                if isinstance(arg, ast.Expression):
                    args.append(arg)
                else:
                    # functionParam → booleanExpression child
                    bool_ctx = getattr(param_ctx, "booleanExpression", lambda: None)()
                    if bool_ctx is not None:
                        nested_arg = self.visit(bool_ctx)
                        if isinstance(nested_arg, ast.Expression):
                            args.append(nested_arg)
        elif callable(expr_getter):
            for expr_ctx in expr_getter() or []:
                arg = self.visit(expr_ctx)
                if isinstance(arg, ast.Expression):
                    args.append(arg)
        nested = None
        if name in NESTED_QUERY_FUNCTIONS and args:
            text_arg = self._expression_string(args[0])
            if text_arg is not None:
                nested = ast.NestedQuery(
                    kind=name,  # type: ignore[arg-type]
                    text=text_arg,
                    locus=ast.Locus(line, col),
                    line=line,
                    column=col,
                )
        return ast.FunctionCall(name=name, args=args, nested_query=nested, line=line, column=col)

    def visitQualifiedName(self, ctx: Any) -> ast.ColumnRef:
        line, col = _line_col(ctx)
        return ast.ColumnRef(name=self._visit_qualified_name(ctx), line=line, column=col)

    def visitQualifiedNamePattern(self, ctx: Any) -> ast.Expression | None:
        text = _text(ctx)
        if "*" in text:
            return ast.Wildcard(pattern=text)
        return ast.ColumnRef(name=text.replace("`", ""))

    def visitLiteralValue(self, ctx: Any) -> ast.Literal | None:
        line, col = _line_col(ctx)
        text = _text(ctx)
        if text.lower() == "null":
            return ast.Literal(value=None, kind="null", line=line, column=col)
        if text.lower() in {"true", "false"}:
            return ast.Literal(value=text.lower() == "true", kind="boolean", line=line, column=col)
        if text.startswith('"') or text.startswith("'") or text.startswith('"""'):
            return ast.Literal(value=_strip_quotes(text), kind="string", line=line, column=col)
        try:
            if "." in text:
                return ast.Literal(value=float(text), kind="double", line=line, column=col)
            return ast.Literal(value=int(text), kind="long", line=line, column=col)
        except ValueError:
            return ast.Literal(value=text, kind="string", line=line, column=col)

    def visitField(self, ctx: Any) -> ast.Alias | ast.ColumnRef | None:
        return self._visit_field_alias(ctx)

    # --- helpers ---

    def _visit_index_pattern(self, ctx: Any) -> str:
        pattern_ctx = ctx.indexPattern()
        if pattern_ctx is not None:
            return _text(pattern_ctx).strip("`")
        sub_ctx = ctx.subquery()
        if sub_ctx is not None:
            return _text(sub_ctx)
        return _text(ctx).strip("`")

    def _visit_name_patterns(self, ctx: Any | None) -> tuple[list[str], list[str]]:
        columns: list[str] = []
        wildcards: list[str] = []
        if ctx is None:
            return columns, wildcards
        for pattern_ctx in ctx.qualifiedNamePattern() or []:
            text = _text(pattern_ctx).replace("`", "")
            if "*" in text:
                wildcards.append(text)
            else:
                columns.append(text)
        return columns, wildcards

    def _visit_field_alias(self, ctx: Any) -> ast.Alias | None:
        line, col = _line_col(ctx)
        name: str | None = None
        expr: ast.Expression | None = None
        qn = ctx.qualifiedName()
        if qn is not None and ctx.ASSIGN() is not None:
            name = self._visit_qualified_name(qn)
        if ctx.booleanExpression() is not None:
            expr = self.visit(ctx.booleanExpression())
        if name is None and isinstance(expr, ast.ColumnRef):
            name = expr.name
        if name and isinstance(expr, ast.Expression):
            return ast.Alias(name=name, expr=expr, line=line, column=col)
        return expr if isinstance(expr, ast.Expression) else None

    def _primary_field_name(self, ctx: Any) -> str | None:
        if ctx is None:
            return None
        visited = self.visit(ctx)
        if isinstance(visited, ast.ColumnRef):
            return visited.name
        text = _text(ctx).replace("`", "")
        return text or None

    def _visit_qualified_field(self, ctx: Any) -> str | None:
        if ctx.qualifiedName() is not None:
            return self._visit_qualified_name(ctx.qualifiedName())
        return _text(ctx).replace("`", "") or None

    def _visit_qualified_name(self, ctx: Any) -> str:
        """Extract a dotted name across grammar snapshots (8.19 vs 9.x shapes)."""
        # Prefer raw text — works for identifierOrParameter chains and modern fieldName forms.
        raw = _text(ctx).replace("`", "")
        if raw:
            return raw
        parts: list[str] = []
        unquoted = getattr(ctx, "UNQUOTED_IDENTIFIER", lambda: None)()
        if unquoted is not None:
            parts.append(unquoted.getText() if hasattr(unquoted, "getText") else _text(unquoted))
        field = getattr(ctx, "fieldName", lambda: None)()
        if field is not None:
            parts.append(_text(field).strip("`"))
        return ".".join(parts) if parts else ""

    def _visit_like_rlike(self, ctx: Any, fn_base: str) -> ast.FunctionCall | None:
        line, col = _line_col(ctx)
        value_ctx = ctx.valueExpression()
        value = self.visit(value_ctx) if value_ctx is not None else None
        if not isinstance(value, ast.Expression):
            return None
        patterns: list[ast.Expression] = []
        for pattern_ctx in self._string_or_parameter_contexts(ctx):
            pattern = self._visit_string_or_parameter(pattern_ctx)
            if isinstance(pattern, ast.Expression):
                patterns.append(pattern)
        name = f"not_{fn_base}" if ctx.NOT() is not None else fn_base
        return ast.FunctionCall(name=name, args=[value, *patterns], line=line, column=col)

    @staticmethod
    def _string_or_parameter_contexts(ctx: Any) -> list[Any]:
        # 9.x+: stringOrParameter(); 8.19: string()
        for attr in ("stringOrParameter", "string"):
            getter = getattr(ctx, attr, None)
            if getter is None:
                continue
            sop = getter()
            if sop is None:
                continue
            if isinstance(sop, list):
                return sop
            return [sop]
        return []

    def _visit_string_or_parameter(self, ctx: Any) -> ast.Expression | None:
        line, col = _line_col(ctx)
        # Direct string rule context (8.19 LIKE string)
        if hasattr(ctx, "QUOTED_STRING") and ctx.QUOTED_STRING() is not None:
            return ast.Literal(
                value=_strip_quotes(ctx.QUOTED_STRING().getText()),
                kind="string",
                line=line,
                column=col,
            )
        string_ctx = getattr(ctx, "string", lambda: None)()
        if string_ctx is not None:
            token = getattr(string_ctx, "QUOTED_STRING", lambda: None)()
            if token is not None:
                return ast.Literal(
                    value=_strip_quotes(token.getText()),
                    kind="string",
                    line=line,
                    column=col,
                )
            return ast.Literal(value=_strip_quotes(_text(string_ctx)), kind="string", line=line, column=col)
        param_ctx = getattr(ctx, "parameter", lambda: None)()
        if param_ctx is not None:
            return ast.ColumnRef(name=_text(param_ctx), line=line, column=col)
        # Fallback: treat whole context text as a quoted string
        raw = _text(ctx)
        if raw:
            return ast.Literal(value=_strip_quotes(raw), kind="string", line=line, column=col)
        return None

    @staticmethod
    def _expression_string(expr: ast.Expression) -> str | None:
        if isinstance(expr, ast.Literal) and isinstance(expr.value, str):
            return expr.value
        return None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _grok_output_fields(pattern: str) -> list[str]:
    fields: list[str] = []
    for match in _GROK_FIELD_RE.finditer(pattern):
        name = match.group(1)
        if name:
            fields.append(name)
    for match in _GROK_NAMED_GROUP_RE.finditer(pattern):
        name = match.group(1) or match.group(2)
        if name:
            fields.append(name)
    return fields


def _dissect_output_fields(pattern: str) -> list[str]:
    fields: list[str] = []
    for match in _DISSECT_FIELD_RE.finditer(pattern):
        name = _DISSECT_MODIFIER_RE.sub("", (match.group(1) or "").strip())
        if name:
            fields.append(name)
    return fields


def build_ast(tree: Any) -> ast.EsqlQuery:
    """Build an `EsqlQuery` from a parse tree root context."""
    builder = AstBuilder()
    result = builder.visit(tree)
    if isinstance(result, ast.EsqlQuery):
        return result
    if isinstance(result, ast.Command):
        return ast.EsqlQuery(commands=[result])
    return ast.EsqlQuery()
