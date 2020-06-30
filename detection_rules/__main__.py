# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# coding=utf-8
"""Shell for detection-rules."""
import os
import click
from .main import root

CURR_DIR = os.path.dirname(os.path.abspath(__file__))
CLI_DIR = os.path.dirname(CURR_DIR)
ROOT_DIR = os.path.dirname(CLI_DIR)

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
