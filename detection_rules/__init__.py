# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Detection rules."""

import sys

from pkg_resources import DistributionNotFound

assert (3, 8) <= sys.version_info < (4, 0), "Only Python 3.8+ supported"

from . import (  # noqa: E402
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

try:
    # use version from etc/packages.yml to build package
    with open("VERSION.txt", 'w') as f:
        f.write(misc.load_current_package_version())
except DistributionNotFound:
    pass  # package is not installed
