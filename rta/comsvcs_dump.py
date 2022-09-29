# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Memory Dump via Comsvcs
# RTA: comsvcs_dump.py
# ATT&CK: T1117
# Description: Invokes comsvcs.dll with rundll32.exe to mimic creating a process MiniDump.

import os
import time

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="413cf7ef-0fad-46fd-ab67-e94c4e3e0f0b",
    platforms=["windows"],
    endpoint=[],
    siem=[
        {
            "rule_id": "c5c9f591-d111-4cf8-baec-c26a39bc31ef",
            "rule_name": "Potential Credential Access via Renamed COM+ Services DLL",
        },
        {"rule_id": "208dbe77-01ed-4954-8d44-1e5751cb20de", "rule_name": "LSASS Memory Dump Handle Access"},
        {
            "rule_id": "00140285-b827-4aee-aa09-8113f58a08f3",
            "rule_name": "Potential Credential Access via Windows Utilities",
        },
    ],
    techniques=["T1003"],
)


@common.requires_os(metadata.platforms)
def main():
    common.log("Memory Dump via Comsvcs")
    pid = os.getpid()
    common.execute(
        [
            "powershell.exe",
            "-c",
            "rundll32.exe",
            "C:\\Windows\\System32\\comsvcs.dll",
            "MiniDump",
            "{} dump.bin full".format(pid),
        ]
    )
    time.sleep(1)
    common.remove_file("dump.bin")


if __name__ == "__main__":
    exit(main())
