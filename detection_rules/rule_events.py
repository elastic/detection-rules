# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions for generating event documents that would trigger a given rule."""

from typing import List

from .rule import AnyRuleData

def _generate_eql_docs(rule: AnyRuleData) -> List[str]:
    from eql import ast
    rule_ast = rule.validator.ast
    data = {"rule.name": rule.name, "rule.language": rule.language}
#    print(f"ast.first:\n{ast.first}\n")
    return [data]

def _generate_kuery_docs(rule: AnyRuleData) -> List[str]:
    from kql import ast
    rule_ast = rule.validator.ast
    data = {"rule.name": rule.name, "rule.language": rule.language}
#    print(f"ast.items:\n{ast.items}\n")
    return [data]

def _generate_lucene_docs(rule: AnyRuleData) -> List[str]:
    from kql import ast
    data = {"rule.name": rule.name, "rule.language": rule.language}
    return [data]

def _generate_error_docs(rule: AnyRuleData, message: str) -> List[str]:
    return [{"rule.name": rule.name, "error.message": message}]

def generate_event_docs(rule: AnyRuleData) -> List[str]:
    # print(f"name:\n{rule.name}\n")
    # print(f"language:\n{rule.language}\n")
    # print(f"index:\n{rule.index}\n")
    # print(f"unique_fields:\n{rule.validator.unique_fields}\n")
    # print(f"query:\n{rule.query}")

    # print(f"ast:\n{ast}\n")
    # print(f"slots:\n{[name for name in ast.iter_slots()]}\n")

    if rule.type not in ("query", "eql"):
        docs = _generate_error_docs(rule, f"Unsupported rule type: {rule.type}")
    elif rule.language == "eql":
        docs = _generate_eql_docs(rule)
    elif rule.language == "kuery":
        docs = _generate_kuery_docs(rule)
    elif rule.language == "lucene":
        docs = _generate_lucene_docs(rule)
    else:
        docs = _generate_error_docs(rule, f"Unsupported rule language: {rule.language}")

    return docs
