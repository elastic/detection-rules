# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Detection rules."""
import sys

assert (3, 8) <= sys.version_info < (4, 0), "Only Python 3.8+ supported"

from . import (  # noqa: E402
    devtools,
    docs,
    eswrap,
    kbwrap,
    main,
    mappings,
    misc,
    rule_formatter,
    rule_loader,
    schemas,
    utils
)

__all__ = (
    'devtools',
    'docs',
    'eswrap',
    'kbwrap',
    'mappings',
    "main",
    'misc',
    'rule_formatter',
    'rule_loader',
    'schemas',
    'utils',
)
