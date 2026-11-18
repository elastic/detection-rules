# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Syntax validation for Lucene regular expressions.

`eql.parse_query()` accepts any string as the pattern of `regex`/`regex~`, but Elasticsearch compiles it with
Lucene's `RegExp` using all optional operators enabled (`RegExp.ALL`, plus complement). This means characters such as
`&`, `<`, `>`, `~`, `#`, `@` and `"` are operators rather than literals and can make a query that passes local
validation fail in Elasticsearch or Kibana.

This module is a validation-only port of the parser in `org.apache.lucene.util.automaton.RegExp` (Lucene 9.x/10.x).
It raises the same errors Lucene would raise while parsing. It does not build automata, so failures that only occur
during determinization (e.g. an overly complex pattern) are not detected.

https://www.elastic.co/docs/reference/query-languages/query-dsl/regexp-syntax
"""

WORD_ESCAPES = "\\ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
INVALID_ESCAPES = "abcefghijklmnopqrtuvxyzABCEFGHIJKLMNOPQRTUVXYZ"
DIGITS = "0123456789"
JAVA_INT_MAX = 2**31 - 1


class LuceneRegexError(ValueError):
    """Error raised when a pattern would be rejected by Lucene's regex parser."""

    def __init__(self, message: str, pattern: str) -> None:
        self.pattern = pattern
        super().__init__(f"Invalid Lucene regex {pattern!r}: {message}")


class _LuceneRegexParser:
    """Recursive descent parser mirroring Lucene's `RegExp` grammar with all syntax flags enabled."""

    def __init__(self, pattern: str) -> None:
        self.pattern = pattern
        self.pos = 0

    def error(self, message: str) -> LuceneRegexError:
        return LuceneRegexError(message, self.pattern)

    def more(self) -> bool:
        return self.pos < len(self.pattern)

    def peek(self, chars: str) -> bool:
        return self.more() and self.pattern[self.pos] in chars

    def match(self, char: str) -> bool:
        if self.more() and self.pattern[self.pos] == char:
            self.pos += 1
            return True
        return False

    def next(self) -> str:
        if not self.more():
            raise self.error("unexpected end-of-string")
        char = self.pattern[self.pos]
        self.pos += 1
        return char

    def parse(self) -> None:
        if not self.pattern:
            return
        self.parse_union()
        if self.more():
            raise self.error(f"end-of-string expected at position {self.pos}")

    def parse_union(self) -> None:
        self.parse_inter()
        while self.match("|"):
            self.parse_inter()

    def parse_inter(self) -> None:
        self.parse_concat()
        while self.match("&"):
            self.parse_concat()

    def parse_concat(self) -> None:
        self.parse_repeat()
        while self.more() and not self.peek(")|&"):
            self.parse_repeat()

    def parse_repeat(self) -> None:
        self.parse_complement()
        while self.peek("?*+{"):
            if self.match("{"):
                start = self.pos
                while self.peek(DIGITS):
                    _ = self.next()
                if start == self.pos:
                    raise self.error(f"integer expected at position {self.pos}")
                n = self.parse_int(self.pattern[start : self.pos])
                m = n
                if self.match(","):
                    start = self.pos
                    while self.peek(DIGITS):
                        _ = self.next()
                    m = self.parse_int(self.pattern[start : self.pos]) if start != self.pos else -1
                if not self.match("}"):
                    raise self.error(f"expected '}}' at position {self.pos}")
                if m != -1 and n > m:
                    raise self.error(f"invalid repetition range(out of order): {n}..{m}")
            else:
                _ = self.next()

    def parse_complement(self) -> None:
        # Elasticsearch enables the (deprecated in Lucene 10) complement operator
        while self.match("~"):
            pass
        self.parse_char_class_exp()

    def parse_char_class_exp(self) -> None:
        if self.match("["):
            _ = self.match("^")
            self.parse_char_classes()
            if not self.match("]"):
                raise self.error(f"expected ']' at position {self.pos}")
        else:
            self.parse_simple()

    def parse_char_classes(self) -> None:
        while True:
            if self.match("\\"):
                if self.peek(WORD_ESCAPES):
                    self.expand_predefined()
                else:
                    _ = self.next()
            else:
                start = self.parse_char()
                if self.match("-"):
                    end = self.parse_char()
                    if start > end:
                        raise self.error(f"invalid range: from ({ord(start)}) cannot be > to ({ord(end)})")
            if not (self.more() and not self.peek("]")):
                break

    def expand_predefined(self) -> None:
        if self.peek(INVALID_ESCAPES):
            raise self.error(f"invalid character class \\{self.next()}")
        _ = self.next()

    def parse_simple(self) -> None:  # noqa: PLR0912
        if self.match(".") or self.match("#") or self.match("@"):
            return
        if self.match('"'):
            while self.more() and not self.peek('"'):
                _ = self.next()
            if not self.match('"'):
                raise self.error(f"expected '\"' at position {self.pos}")
        elif self.match("("):
            if self.match(")"):
                return
            self.parse_union()
            if not self.match(")"):
                raise self.error(f"expected ')' at position {self.pos}")
        elif self.match("<"):
            start = self.pos
            while self.more() and not self.peek(">"):
                _ = self.next()
            if not self.match(">"):
                raise self.error(f"expected '>' at position {self.pos}")
            self.check_interval(self.pattern[start : self.pos - 1])
        elif self.match("\\"):
            if self.peek(WORD_ESCAPES):
                self.expand_predefined()
            else:
                _ = self.next()
        else:
            _ = self.next()

    def check_interval(self, body: str) -> None:
        if "-" not in body:
            # Named automata require an automaton provider, which Elasticsearch never supplies
            raise self.error(f"'{body}' not found (named automaton '<{body}>' is not supported)")
        i = body.index("-")
        smin, smax = body[:i], body[i + 1 :]
        if i == 0 or i == len(body) - 1 or "-" in smax or not smin.isdigit() or not smax.isdigit():
            raise self.error(f"interval syntax error at position {self.pos - 1}")
        _ = self.parse_int(smin), self.parse_int(smax)

    def parse_int(self, value: str) -> int:
        number = int(value)
        if number > JAVA_INT_MAX:
            raise self.error(f'number too large for a Java int: "{value}"')
        return number

    def parse_char(self) -> str:
        _ = self.match("\\")
        return self.next()


def validate_lucene_regex(pattern: str) -> None:
    """Raise a `LuceneRegexError` if Elasticsearch would fail to parse `pattern` as a Lucene regex."""
    _LuceneRegexParser(pattern).parse()
