# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Detection Rules tests."""
import glob
import json
import os

from detection_rules.utils import combine_sources

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(CURRENT_DIR, 'data')
TP_DIR = os.path.join(DATA_DIR, 'true_positives')
FP_DIR = os.path.join(DATA_DIR, 'false_positives')


def get_fp_dirs():
    """Get a list of fp dir names."""
    return glob.glob(os.path.join(FP_DIR, '*'))


def get_fp_data_files():
    """get FP data files by fp dir name."""
    data = {}
    for fp_dir in get_fp_dirs():
        fp_dir_name = os.path.basename(fp_dir)
        relative_dir_name = os.path.join('false_positives', fp_dir_name)
        data[fp_dir_name] = combine_sources(*get_data_files(relative_dir_name).values())

    return data


def get_data_files_list(*folder, ext='jsonl', recursive=False):
    """Get TP or FP file list."""
    folder = os.path.sep.join(folder)
    data_dir = [DATA_DIR, folder]
    if recursive:
        data_dir.append('**')

    data_dir.append('*.{}'.format(ext))
    return glob.glob(os.path.join(*data_dir), recursive=recursive)


def get_data_files(*folder, ext='jsonl', recursive=False):
    """Get data from data files."""
    data_files = {}
    for data_file in get_data_files_list(*folder, ext=ext, recursive=recursive):
        with open(data_file, 'r') as f:
            file_name = os.path.splitext(os.path.basename(data_file))[0]

            if ext == 'jsonl':
                data = f.readlines()
                data_files[file_name] = [json.loads(d) for d in data]
            else:
                data_files[file_name] = json.load(f)

    return data_files


def get_data_file(*folder):
    file = os.path.join(DATA_DIR, os.path.sep.join(folder))
    if os.path.exists(file):
        with open(file, 'r') as f:
            return json.load(f)
