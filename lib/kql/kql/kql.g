?query: or_query
?or_query: and_query (OR and_query)*
?and_query: not_query (AND not_query)*
?not_query: NOT? sub_query
?sub_query: "(" or_query ")"
         | nested_query
?nested_query: field ":" "{" or_query "}"
             | expression
?expression: field_range_expression
           | field_value_expression
           | value_expression

field_range_expression: field RANGE_OPERATOR literal
field_value_expression: field ":" list_of_values
?value_expression: value

?list_of_values: "(" or_list_of_values ")"
               | optional_not value
?optional_not: NOT optional_not
              |
?or_list_of_values:  and_list_of_values (OR and_list_of_values)*
?and_list_of_values: not_list_of_values (AND not_list_of_values)*
?not_list_of_values: NOT? list_of_values

field: literal

value: QUOTED_STRING
      | WILDCARD_LITERAL
      | UNQUOTED_LITERAL


literal: QUOTED_STRING
        | UNQUOTED_LITERAL

RANGE_OPERATOR: "<="
              | ">="
              | "<"
              | ">"

// Wildcard literal - for wildcard values containing spaces
// Priority 3 ensures it matches before keywords (priority 2) and unquoted literals
// Uses word boundary \b to stop before 'or', 'and', 'not' keywords
// MUST contain at least one space to differentiate from field names like common.*
// Must not start with not/or/and so "not /tmp/go-build*" is not matched (value is UNQUOTED_LITERAL)
// Pattern 1: Starts with * (e.g., *S3 Browser, *S3 Browser*)
// Pattern 2: Ends with * but doesn't start with * (e.g., S3 Browser*)
// Pattern 3a: Middle * - star appears AFTER a space (e.g., S3 B*owser)
// Pattern 3b: Middle * - star appears BEFORE a space (e.g., S3* Browser)
WILDCARD_LITERAL.3: /\*[^\s\r\n()"':{}]*(?:\s+(?!(?:or|and|not)\b)[^\s\r\n()"':{}]+)+\*?/i
                  | /(?!(?:not|or|and)\b)[^\s\r\n()"':{}][^\s\r\n()"':{}]*(?:\s+(?!(?:or|and|not)\b)[^\s\r\n()"':{}]+)+\*/i
                  | /(?!(?:not|or|and)\b)[^\s\r\n()"'*:{}][^\s\r\n()"':{}]*\s+(?!(?:or|and|not)\b)[^\s\r\n()"':{}]*\*[^\s\r\n()"':{}]+(?:\s+(?!(?:or|and|not)\b)[^\s\r\n()"':{}]+)*(?<!\*)/i
                  | /(?!(?:not|or|and)\b)[^\s\r\n()"'*:{}][^\s\r\n()"':{}]*\*[^\s\r\n()"':{}]*\s+(?!(?:or|and|not)\b)[^\s\r\n()"':{}]+(?:\s+(?!(?:or|and|not)\b)[^\s\r\n()"':{}]+)*(?<!\*)/i

UNQUOTED_LITERAL: UNQUOTED_CHAR+
UNQUOTED_CHAR: "\\" /[trn]/              // escaped whitespace
             | "\\" /[\\():<>"*{}]/      // escaped specials
             | "\\" (AND | OR | NOT)     // escaped keywords
             | "*"                       // wildcard
             | /[^\\():<>"*{} \t\r\n]/   // anything else

QUOTED_STRING: /"(\\[tnr"\\]|[^\r\n"])*"/

OR.2: "or" | "OR"
AND.2: "and" | "AND"
NOT.2: "not" | "NOT"

WHITESPACE: (" " | "\r" | "\n" | "\t" )+
%ignore WHITESPACE