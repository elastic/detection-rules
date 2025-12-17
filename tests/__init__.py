# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Detection Rules tests."""

import json
import os
import pathlib

from detection_rules.eswrap import combine_sources

CURRENT_DIR = pathlib.Path(__file__).resolve().parent
DATA_DIR = CURRENT_DIR / "data"
TP_DIR = DATA_DIR / "true_positives"
FP_DIR = DATA_DIR / "false_positives"


def get_fp_dirs():
    """Get a list of fp dir names."""
    return FP_DIR.glob("*")


def get_fp_data_files():
    """get FP data files by fp dir name."""
    data = {}
    for fp_dir in get_fp_dirs():
        path = pathlib.Path(fp_dir)
        fp_dir_name = path.name
        relative_dir_name = pathlib.Path("false_positives") / fp_dir_name
        data[fp_dir_name] = combine_sources(*get_data_files(relative_dir_name).values())

    return data


def get_data_files_list(*folder, ext="ndjson", recursive=False):
    """Get TP or FP file list."""
    folder = os.path.sep.join(folder)
    data_dir = pathlib.Path(DATA_DIR) / folder

    glob = "**" if recursive else ""
    glob += f"*.{ext}"

    return data_dir.glob(glob)


def get_data_files(*folder, ext="ndjson", recursive=False):
    """Get data from data files."""
    data_files = {}
    for data_file in get_data_files_list(*folder, ext=ext, recursive=recursive):
        path = pathlib.Path(data_file)
        with path.open() as f:
            file_name = path.stem

            if ext in (".ndjson", ".jsonl"):
                data = f.readlines()
                data_files[file_name] = [json.loads(d) for d in data]
            else:
                data_files[file_name] = json.load(f)

    return data_files


def get_data_file(*folder):
    path = pathlib.Path(DATA_DIR) / os.path.sep.join(folder)
    if path.exists():
        with path.open() as f:
            return json.load(f)
    return None
