# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import importlib
from pathlib import Path
from typing import List, Optional

from . import common

CURRENT_DIR = Path(__file__).resolve().parent


def get_ttp_list(os_types: Optional[List[str]] = None) -> List[str]:
    scripts = []
    if os_types and not isinstance(os_types, (list, tuple)):
        os_types = [os_types]

    for script in CURRENT_DIR.glob("*.py"):
        base_name = script.stem
        if base_name not in ("common", "main") and not base_name.startswith("_"):
            if os_types:
                # Import it and skip it if it's not supported
                importlib.import_module(__name__ + "." + base_name)
                if not any(base_name in common.OS_MAPPING[os_type] for os_type in os_types):
                    continue

            scripts.append(str(script))

    return scripts


def get_ttp_names(os_types: Optional[List[str]] = None) -> List[str]:
    names = []
    for script in get_ttp_list(os_types):
        basename = Path(script).stem
        names.append(basename)
    return names


__all__ = (
    "common"
)
