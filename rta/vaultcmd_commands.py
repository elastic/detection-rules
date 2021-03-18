# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Searching Credential Vaults via VaultCmd
# RTA: vaultcmd_commands.py
# ATT&CK: T1003
# Description: Lists the Windows Credential Vaults on the endpoint

import sys

from . import common


@common.requires_os(common.WINDOWS)
def main():
    common.log("Searching Credential Vaults via VaultCmd")

    common.execute(["vaultcmd.exe", "/list"])


if __name__ == "__main__":
    exit(main(*sys.argv[1:]))
