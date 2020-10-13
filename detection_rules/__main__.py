# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# coding=utf-8
"""Shell for detection-rules."""
from pathlib import Path
import click
from .main import root

CURR_DIR = Path(__file__).parent
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
