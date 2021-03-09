# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Powershell with Suspicious Arguments
# RTA: powershell_args.py
# ATT&CK: T1140
# Description: Calls PowerShell with suspicious command line arguments.

import base64
import os

from . import common


def encode(command):
    return base64.b64encode(command.encode('utf-16le'))


@common.requires_os(common.WINDOWS)
def main():
    common.log("PowerShell Suspicious Commands")
    temp_script = os.path.abspath("tmp.ps1")

    # Create an empty script
    with open(temp_script, "w") as f:
        f.write("whoami.exe\nexit\n")

    powershell_commands = [
        ['powershell.exe', '-ExecutionPol', 'Bypass', temp_script],
        ['powershell.exe', 'iex', 'Get-Process'],
        ['powershell.exe', '-ec', encode('Get-Process' + ' ' * 1000)],
    ]

    for command in powershell_commands:
        common.execute(command)

    common.remove_file(temp_script)


if __name__ == "__main__":
    exit(main())
