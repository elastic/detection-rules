# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# coding=utf-8
"""Shell for detection-rules."""
import os
import sys

import click

assert (3, 12) <= sys.version_info < (4, 0), "Only Python 3.12+ supported"

from pathlib import Path

from .main import root  # noqa: E402

CURR_DIR = Path(__file__).resolve().parent
CLI_DIR = CURR_DIR.parent
ROOT_DIR = CLI_DIR.parent

BANNER = r"""
█▀▀▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄   ▄      █▀▀▄ ▄  ▄ ▄   ▄▄▄ ▄▄▄
█  █ █▄▄  █  █▄▄ █    █   █  █ █ █▀▄ █      █▄▄▀ █  █ █   █▄▄ █▄▄
█▄▄▀ █▄▄  █  █▄▄ █▄▄  █  ▄█▄ █▄█ █ ▀▄█      █ ▀▄ █▄▄█ █▄▄ █▄▄ ▄▄█
"""


def main():
    """CLI entry point."""
    click.echo(BANNER)
    root(prog_name="detection_rules")


main()
