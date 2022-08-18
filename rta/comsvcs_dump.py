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

PLATFORMS = [common.WINDOWS]
TRIGGERED_RULES = {
    "SIEM": ["Potential Credential Access via Renamed COM+ Services DLL",
             "LSASS Memory Dump Handle Access",
             "Potential Credential Access via Windows Utilities"
            ],
    "ENDPOINT": []
}

@common.requires_os(PLATFORMS)
def main():
    common.log("Memory Dump via Comsvcs")
    pid = os.getpid()
    common.execute(["powershell.exe", "-c", "rundll32.exe", "C:\\Windows\\System32\\comsvcs.dll",
                    "MiniDump", "{} dump.bin full".format(pid)])
    time.sleep(1)
    common.remove_file("dump.bin")


if __name__ == "__main__":
    exit(main())
