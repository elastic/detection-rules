# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
"""Factory for creating ESQL listeners."""


class IESQLListener:
    """
    Interface for ESQL listeners.
    This interface defines the methods that any ESQL listener should implement.
    """

    def enterQualifiedName(self, ctx):  # noqa: N802
        raise NotImplementedError

    def enterSourceIdentifier(self, ctx):  # noqa: N802
        raise NotImplementedError

    def enterSingleStatement(self, ctx):  # noqa: N802
        raise NotImplementedError

    def check_literal_type(self, ctx):  # noqa: N802
        raise NotImplementedError

    def find_associated_field_and_context(self, ctx):  # noqa: N802
        raise NotImplementedError

    def get_literal_type(self, ctx):  # noqa: N802
        raise NotImplementedError

    def enterNullLiteral(self, ctx):  # noqa: N802
        raise NotImplementedError

    def enterQualifiedIntegerLiteral(self, ctx):  # noqa: N802
        raise NotImplementedError

    def enterDecimalLiteral(self, ctx):  # noqa: N802
        raise NotImplementedError

    def enterIntegerLiteral(self, ctx):  # noqa: N802
        raise NotImplementedError

    def enterBooleanLiteral(self, ctx):  # noqa: N802
        raise NotImplementedError

    def enterStringLiteral(self, ctx):  # noqa: N802
        raise NotImplementedError

    def enterNumericArrayLiteral(self, ctx):  # noqa: N802
        raise NotImplementedError

    def enterBooleanArrayLiteral(self, ctx):  # noqa: N802
        raise NotImplementedError

    def enterStringArrayLiteral(self, ctx):  # noqa: N802
        raise NotImplementedError

    def enterBooleanDefault(self, ctx):  # noqa: N802
        raise NotImplementedError


class ESQLListenerFactory:
    """ Factory for creating ESQL listeners. """

    @staticmethod
    def getListener(version) -> IESQLListener:  # noqa: N802
        """Return the listener for the given version."""
        if version == '8.11.0':
            from esql.esql_listener_v8_11_0_adapter import ESQLListenerV8_11_0Adapter  # noqa: E501
            return ESQLListenerV8_11_0Adapter()
        else:
            raise ValueError("Unsupported grammar version")
