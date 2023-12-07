# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Factory for creating ESQL parsers."""
from antlr4 import CommonTokenStream, InputStream, Lexer, Parser

from esql.generated.v8_11_0.EsqlBaseLexer import EsqlBaseLexer as EsqlBaseLexerV8_11_0
from esql.generated.v8_11_0.EsqlBaseParser import EsqlBaseParser as EsqlBaseParserV8_11_0


class ESQLParserFactory:
    """Factory for creating ESQL parsers."""

    @staticmethod
    def createParser(query, version) -> Parser:
        """Create a parser for the given ESQL query."""  # noqa: N802
        input_stream = InputStream(query.lower())
        lexer = ESQLParserFactory.createLexer(input_stream, version)
        token_stream = CommonTokenStream(lexer)
        return ESQLParserFactory.getParser(token_stream, version)

    @staticmethod
    def createLexer(input_stream, version) -> Lexer:
        """Create a lexer for the given ESQL query."""  # noqa: N802
        if version == '8.11.0':
            return EsqlBaseLexerV8_11_0(input_stream)
        # Will add other conditions for different versions as they come out
        # ...
        raise ValueError(f"Unsupported version: {version}")

    @staticmethod
    def getParser(token_stream, version) -> Parser:
        """Get the parser for the given ESQL query."""  # noqa: N802
        if version == '8.11.0':
            return EsqlBaseParserV8_11_0(token_stream)
        # Will add other conditions for different versions as they come out
        # ...
        raise ValueError(f"Unsupported version: {version}")
