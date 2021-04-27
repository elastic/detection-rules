# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import glob
import importlib
import os

from . import common

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))


def get_ttp_list(os_types=None):
    scripts = []
    if os_types and not isinstance(os_types, (list, tuple)):
        os_types = [os_types]

    for script in sorted(glob.glob(os.path.join(CURRENT_DIR, "*.py"))):
        base_name, _ = os.path.splitext(os.path.basename(script))
        if base_name not in ("common", "main") and not base_name.startswith("_"):
            if os_types:
                # Import it and skip it if it's not supported
                importlib.import_module(__name__ + "." + base_name)
                if not any(base_name in common.OS_MAPPING[os_type] for os_type in os_types):
                    continue

            scripts.append(script)

    return scripts


def get_ttp_names(os_types=None):
    names = []
    for script in get_ttp_list(os_types):
        basename, ext = os.path.splitext(os.path.basename(script))
        names.append(basename)
    return names


__all__ = (
    "common"
)
