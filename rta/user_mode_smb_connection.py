# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="8ce1099f-26e7-45ea-a7a9-9ab0926a2c4a",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Unexpected SMB Connection from User-mode Process",
            "rule_id": "2fbbd139-3919-4b6b-9c50-9452b0aef005",
        }
    ],
    siem=[],
    techniques=["T1021"],
)


@common.requires_os(metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    posh = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\posh.exe"

    # Execute command
    common.copy_file(powershell, posh)
    common.log("Testing connection to Portquiz at Port 445")
    common.execute(
        [
            posh,
            "/c",
            "Test-NetConnection",
            "-ComputerName",
            "portquiz.net",
            "-Port",
            "445",
        ],
        timeout=10,
    )
    common.remove_files(posh)


if __name__ == "__main__":
    exit(main())
