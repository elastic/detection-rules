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

PLATFORMS = [common.WINDOWS]
TRIGGERED_RULES = {
    "SIEM": [
        {
            "rule_id": "be8afaed-4bcd-4e0a-b5f9-5562003dde81",
            "rule_name": "Searching for Saved Credentials via VaultCmd",
        }
    ],
    "ENDPOINT": [],
}
TACTICS = ["TA0006"]
RTA_ID = "53d071d9-36e3-4b40-83c8-d818bd831010"


@common.requires_os(PLATFORMS)
def main():
    common.log("Searching Credential Vaults via VaultCmd")

    common.execute(["vaultcmd.exe", "/list"])


if __name__ == "__main__":
    exit(main(*sys.argv[1:]))
