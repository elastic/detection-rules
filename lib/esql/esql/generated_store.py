# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Committed generated definitions live as flat per-module ZIP archives.

Layout::

    esql/_generated/<module>.zip   # function_signatures.json (+ optional commands /
                                   # definitions_provenance.json)

Runtime opens members in memory (see `esql.functions`). Generators rewrite the zip.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

_GENERATED_ROOT = Path(__file__).resolve().parent / "_generated"


def module_zip_path(module: str) -> Path:
    return _GENERATED_ROOT / f"{module}.zip"


def read_json_member(module: str, member: str) -> Any | None:
    """Return parsed JSON for *member* inside `<module>.zip`, or None if missing."""
    path = module_zip_path(module)
    if not path.is_file():
        return None
    with zipfile.ZipFile(path) as zf:
        try:
            raw = zf.read(member)
        except KeyError:
            return None
    return json.loads(raw.decode("utf-8"))


def write_module_zip(module: str, members: dict[str, Any]) -> Path:
    """Write *members* (name → JSON-serializable) into `esql/_generated/<module>.zip`."""
    _GENERATED_ROOT.mkdir(parents=True, exist_ok=True)
    dest = module_zip_path(module)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    if tmp.exists():
        tmp.unlink()
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, payload in sorted(members.items()):
            text = json.dumps(payload, indent=2, sort_keys=isinstance(payload, dict)) + "\n"
            zf.writestr(name, text.encode("utf-8"))
    tmp.replace(dest)
    # Remove legacy unpacked directory if present.
    legacy = _GENERATED_ROOT / module
    if legacy.is_dir():
        import shutil

        shutil.rmtree(legacy)
    return dest
