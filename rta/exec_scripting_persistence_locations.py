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
            "rule_name": "Script Interpreter Process Writing to Commonly Abused Persistence Locations",
            "rule_id": "be42f9fc-bdca-41cd-b125-f223d09eef69",
        },
        {
            "rule_name": "Startup Persistence via Windows Script Interpreter",
            "rule_id": "a85000c8-3eac-413b-8353-079343c2b6f0",
        },
    ],
}
TACTICS = ["TA0002", "TA0003"]
RTA_ID = "537de67d-8ba8-4df8-a965-75ca564d0846"


@common.requires_os(PLATFORMS)
def main():

    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    common.log("Dropping executable to Startup Folder using powershell")
    common.execute(
        [
            powershell,
            "-C",
            "Copy-Item",
            "C:\\Windows\\System32\\cmd.exe",
            "'C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\'",
        ]
    )

    common.log("Dropping executable to Startup Folder using powershell")
    common.execute(
        [
            powershell,
            "-C",
            "Copy-Item",
            "C:\\Windows\\System32\\cmd.exe",
            "'C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\cmd2.exe'",
        ]
    )

    common.remove_files(
        "C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\cmd2.exe",
        "C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\cmd.exe",
    )


if __name__ == "__main__":
    exit(main())
