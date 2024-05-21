# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Detection rules."""

import sys


assert (3, 12) <= sys.version_info < (4, 0), "Only Python 3.12+ supported"

from . import (  # noqa: E402
    'custom_schemas',
    custom_rules,
    devtools,
    docs,
    eswrap,
    ghwrap,
    kbwrap,
    main,
    mappings,
    ml,
    misc,
    navigator,
    rule_formatter,
    rule_loader,
    schemas,
    utils
)

__all__ = (
    'custom_rules',
    'custom_schemas',
    'devtools',
    'docs',
    'eswrap',
    'ghwrap',
    'kbwrap',
    'mappings',
    "main",
    'misc',
    'ml',
    'navigator',
    'rule_formatter',
    'rule_loader',
    'schemas',
    'utils'
)
