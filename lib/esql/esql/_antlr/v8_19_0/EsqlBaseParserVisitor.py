# Generated from /var/folders/34/52r9fr3x7kgcv2srt4rgpmcc0000gn/T//esql-gen-8.19.0.jyhQAI/adapted/EsqlBaseParser.g4 by ANTLR 4.13.1
from antlr4 import *
if "." in __name__:
    from .EsqlBaseParser import EsqlBaseParser
else:
    from EsqlBaseParser import EsqlBaseParser

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
# Adapted for python-esql from Elasticsearch antlr sources.


# This class defines a complete generic visitor for a parse tree produced by EsqlBaseParser.

class EsqlBaseParserVisitor(ParseTreeVisitor):

    # Visit a parse tree produced by EsqlBaseParser#singleStatement.
    def visitSingleStatement(self, ctx:EsqlBaseParser.SingleStatementContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#compositeQuery.
    def visitCompositeQuery(self, ctx:EsqlBaseParser.CompositeQueryContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#singleCommandQuery.
    def visitSingleCommandQuery(self, ctx:EsqlBaseParser.SingleCommandQueryContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#sourceCommand.
    def visitSourceCommand(self, ctx:EsqlBaseParser.SourceCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#processingCommand.
    def visitProcessingCommand(self, ctx:EsqlBaseParser.ProcessingCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#whereCommand.
    def visitWhereCommand(self, ctx:EsqlBaseParser.WhereCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#matchExpression.
    def visitMatchExpression(self, ctx:EsqlBaseParser.MatchExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#logicalNot.
    def visitLogicalNot(self, ctx:EsqlBaseParser.LogicalNotContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#booleanDefault.
    def visitBooleanDefault(self, ctx:EsqlBaseParser.BooleanDefaultContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#isNull.
    def visitIsNull(self, ctx:EsqlBaseParser.IsNullContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#regexExpression.
    def visitRegexExpression(self, ctx:EsqlBaseParser.RegexExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#logicalIn.
    def visitLogicalIn(self, ctx:EsqlBaseParser.LogicalInContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#logicalBinary.
    def visitLogicalBinary(self, ctx:EsqlBaseParser.LogicalBinaryContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#likeExpression.
    def visitLikeExpression(self, ctx:EsqlBaseParser.LikeExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#rlikeExpression.
    def visitRlikeExpression(self, ctx:EsqlBaseParser.RlikeExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#likeListExpression.
    def visitLikeListExpression(self, ctx:EsqlBaseParser.LikeListExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#matchBooleanExpression.
    def visitMatchBooleanExpression(self, ctx:EsqlBaseParser.MatchBooleanExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#valueExpressionDefault.
    def visitValueExpressionDefault(self, ctx:EsqlBaseParser.ValueExpressionDefaultContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#comparison.
    def visitComparison(self, ctx:EsqlBaseParser.ComparisonContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#operatorExpressionDefault.
    def visitOperatorExpressionDefault(self, ctx:EsqlBaseParser.OperatorExpressionDefaultContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#arithmeticBinary.
    def visitArithmeticBinary(self, ctx:EsqlBaseParser.ArithmeticBinaryContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#arithmeticUnary.
    def visitArithmeticUnary(self, ctx:EsqlBaseParser.ArithmeticUnaryContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#dereference.
    def visitDereference(self, ctx:EsqlBaseParser.DereferenceContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#inlineCast.
    def visitInlineCast(self, ctx:EsqlBaseParser.InlineCastContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#constantDefault.
    def visitConstantDefault(self, ctx:EsqlBaseParser.ConstantDefaultContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#parenthesizedExpression.
    def visitParenthesizedExpression(self, ctx:EsqlBaseParser.ParenthesizedExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#function.
    def visitFunction(self, ctx:EsqlBaseParser.FunctionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#functionExpression.
    def visitFunctionExpression(self, ctx:EsqlBaseParser.FunctionExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#functionName.
    def visitFunctionName(self, ctx:EsqlBaseParser.FunctionNameContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#mapExpression.
    def visitMapExpression(self, ctx:EsqlBaseParser.MapExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#entryExpression.
    def visitEntryExpression(self, ctx:EsqlBaseParser.EntryExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#toDataType.
    def visitToDataType(self, ctx:EsqlBaseParser.ToDataTypeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#rowCommand.
    def visitRowCommand(self, ctx:EsqlBaseParser.RowCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#fields.
    def visitFields(self, ctx:EsqlBaseParser.FieldsContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#field.
    def visitField(self, ctx:EsqlBaseParser.FieldContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#rerankFields.
    def visitRerankFields(self, ctx:EsqlBaseParser.RerankFieldsContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#rerankField.
    def visitRerankField(self, ctx:EsqlBaseParser.RerankFieldContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#fromCommand.
    def visitFromCommand(self, ctx:EsqlBaseParser.FromCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#indexPattern.
    def visitIndexPattern(self, ctx:EsqlBaseParser.IndexPatternContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#clusterString.
    def visitClusterString(self, ctx:EsqlBaseParser.ClusterStringContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#selectorString.
    def visitSelectorString(self, ctx:EsqlBaseParser.SelectorStringContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#unquotedIndexString.
    def visitUnquotedIndexString(self, ctx:EsqlBaseParser.UnquotedIndexStringContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#indexString.
    def visitIndexString(self, ctx:EsqlBaseParser.IndexStringContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#metadata.
    def visitMetadata(self, ctx:EsqlBaseParser.MetadataContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#metadataOption.
    def visitMetadataOption(self, ctx:EsqlBaseParser.MetadataOptionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#deprecated_metadata.
    def visitDeprecated_metadata(self, ctx:EsqlBaseParser.Deprecated_metadataContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#metricsCommand.
    def visitMetricsCommand(self, ctx:EsqlBaseParser.MetricsCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#evalCommand.
    def visitEvalCommand(self, ctx:EsqlBaseParser.EvalCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#statsCommand.
    def visitStatsCommand(self, ctx:EsqlBaseParser.StatsCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#aggFields.
    def visitAggFields(self, ctx:EsqlBaseParser.AggFieldsContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#aggField.
    def visitAggField(self, ctx:EsqlBaseParser.AggFieldContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#qualifiedName.
    def visitQualifiedName(self, ctx:EsqlBaseParser.QualifiedNameContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#qualifiedNamePattern.
    def visitQualifiedNamePattern(self, ctx:EsqlBaseParser.QualifiedNamePatternContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#qualifiedNamePatterns.
    def visitQualifiedNamePatterns(self, ctx:EsqlBaseParser.QualifiedNamePatternsContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#identifier.
    def visitIdentifier(self, ctx:EsqlBaseParser.IdentifierContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#identifierPattern.
    def visitIdentifierPattern(self, ctx:EsqlBaseParser.IdentifierPatternContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#nullLiteral.
    def visitNullLiteral(self, ctx:EsqlBaseParser.NullLiteralContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#qualifiedIntegerLiteral.
    def visitQualifiedIntegerLiteral(self, ctx:EsqlBaseParser.QualifiedIntegerLiteralContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#decimalLiteral.
    def visitDecimalLiteral(self, ctx:EsqlBaseParser.DecimalLiteralContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#integerLiteral.
    def visitIntegerLiteral(self, ctx:EsqlBaseParser.IntegerLiteralContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#booleanLiteral.
    def visitBooleanLiteral(self, ctx:EsqlBaseParser.BooleanLiteralContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#inputParameter.
    def visitInputParameter(self, ctx:EsqlBaseParser.InputParameterContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#stringLiteral.
    def visitStringLiteral(self, ctx:EsqlBaseParser.StringLiteralContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#numericArrayLiteral.
    def visitNumericArrayLiteral(self, ctx:EsqlBaseParser.NumericArrayLiteralContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#booleanArrayLiteral.
    def visitBooleanArrayLiteral(self, ctx:EsqlBaseParser.BooleanArrayLiteralContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#stringArrayLiteral.
    def visitStringArrayLiteral(self, ctx:EsqlBaseParser.StringArrayLiteralContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#inputParam.
    def visitInputParam(self, ctx:EsqlBaseParser.InputParamContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#inputNamedOrPositionalParam.
    def visitInputNamedOrPositionalParam(self, ctx:EsqlBaseParser.InputNamedOrPositionalParamContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#inputDoubleParams.
    def visitInputDoubleParams(self, ctx:EsqlBaseParser.InputDoubleParamsContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#inputNamedOrPositionalDoubleParams.
    def visitInputNamedOrPositionalDoubleParams(self, ctx:EsqlBaseParser.InputNamedOrPositionalDoubleParamsContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#identifierOrParameter.
    def visitIdentifierOrParameter(self, ctx:EsqlBaseParser.IdentifierOrParameterContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#limitCommand.
    def visitLimitCommand(self, ctx:EsqlBaseParser.LimitCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#sortCommand.
    def visitSortCommand(self, ctx:EsqlBaseParser.SortCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#orderExpression.
    def visitOrderExpression(self, ctx:EsqlBaseParser.OrderExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#keepCommand.
    def visitKeepCommand(self, ctx:EsqlBaseParser.KeepCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#dropCommand.
    def visitDropCommand(self, ctx:EsqlBaseParser.DropCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#renameCommand.
    def visitRenameCommand(self, ctx:EsqlBaseParser.RenameCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#renameClause.
    def visitRenameClause(self, ctx:EsqlBaseParser.RenameClauseContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#dissectCommand.
    def visitDissectCommand(self, ctx:EsqlBaseParser.DissectCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#grokCommand.
    def visitGrokCommand(self, ctx:EsqlBaseParser.GrokCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#mvExpandCommand.
    def visitMvExpandCommand(self, ctx:EsqlBaseParser.MvExpandCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#commandOptions.
    def visitCommandOptions(self, ctx:EsqlBaseParser.CommandOptionsContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#commandOption.
    def visitCommandOption(self, ctx:EsqlBaseParser.CommandOptionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#booleanValue.
    def visitBooleanValue(self, ctx:EsqlBaseParser.BooleanValueContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#numericValue.
    def visitNumericValue(self, ctx:EsqlBaseParser.NumericValueContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#decimalValue.
    def visitDecimalValue(self, ctx:EsqlBaseParser.DecimalValueContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#integerValue.
    def visitIntegerValue(self, ctx:EsqlBaseParser.IntegerValueContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#string.
    def visitString(self, ctx:EsqlBaseParser.StringContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#comparisonOperator.
    def visitComparisonOperator(self, ctx:EsqlBaseParser.ComparisonOperatorContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#explainCommand.
    def visitExplainCommand(self, ctx:EsqlBaseParser.ExplainCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#subqueryExpression.
    def visitSubqueryExpression(self, ctx:EsqlBaseParser.SubqueryExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#showInfo.
    def visitShowInfo(self, ctx:EsqlBaseParser.ShowInfoContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#enrichCommand.
    def visitEnrichCommand(self, ctx:EsqlBaseParser.EnrichCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#enrichPolicyName.
    def visitEnrichPolicyName(self, ctx:EsqlBaseParser.EnrichPolicyNameContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#enrichWithClause.
    def visitEnrichWithClause(self, ctx:EsqlBaseParser.EnrichWithClauseContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#changePointCommand.
    def visitChangePointCommand(self, ctx:EsqlBaseParser.ChangePointCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#sampleCommand.
    def visitSampleCommand(self, ctx:EsqlBaseParser.SampleCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#lookupCommand.
    def visitLookupCommand(self, ctx:EsqlBaseParser.LookupCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#inlinestatsCommand.
    def visitInlinestatsCommand(self, ctx:EsqlBaseParser.InlinestatsCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#joinCommand.
    def visitJoinCommand(self, ctx:EsqlBaseParser.JoinCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#joinTarget.
    def visitJoinTarget(self, ctx:EsqlBaseParser.JoinTargetContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#joinCondition.
    def visitJoinCondition(self, ctx:EsqlBaseParser.JoinConditionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#joinPredicate.
    def visitJoinPredicate(self, ctx:EsqlBaseParser.JoinPredicateContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#inferenceCommandOptions.
    def visitInferenceCommandOptions(self, ctx:EsqlBaseParser.InferenceCommandOptionsContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#inferenceCommandOption.
    def visitInferenceCommandOption(self, ctx:EsqlBaseParser.InferenceCommandOptionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#inferenceCommandOptionValue.
    def visitInferenceCommandOptionValue(self, ctx:EsqlBaseParser.InferenceCommandOptionValueContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#rerankCommand.
    def visitRerankCommand(self, ctx:EsqlBaseParser.RerankCommandContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by EsqlBaseParser#completionCommand.
    def visitCompletionCommand(self, ctx:EsqlBaseParser.CompletionCommandContext):
        return self.visitChildren(ctx)



del EsqlBaseParser