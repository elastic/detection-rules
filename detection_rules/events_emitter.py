# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Functions for generating event documents that would trigger a given rule."""

import time
from typing import List

from .rule import AnyRuleData

def _generate_error_docs(message: str) -> List[str]:
    return [{"error.message": message}]

def emit_events(rule: AnyRuleData) -> List[str]:
    if rule.type not in ("query", "eql"):
        docs = _generate_error_docs(f"Unsupported rule type: {rule.type}")
    elif rule.language == "eql":
        from .events_emitter_eql import emit_events_eql
        docs = emit_events_eql(rule.validator.ast)
    else:
        docs = _generate_error_docs(f"Unsupported query language: {rule.language}")

    for doc in docs:
        doc.update({
            "@timestamp": int(time.time() * 1000),
            "rule.name": rule.name,
        })
    return docs
