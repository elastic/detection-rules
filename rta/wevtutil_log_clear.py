# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Clearing Windows Event Logs
# RTA: wevutil_log_clear.py
# signal.rule.name: Clearing Windows Event Logs
# ATT&CK: T1070
# Description: Uses the native Windows Event utility to clear the Security, Application and System event logs.

import time

from . import common


@common.requires_os(common.WINDOWS)
def main():
    common.log("Clearing Windows Event Logs")
    common.log("WARNING - About to clear logs from Windows Event Viewer", log_type="!")
    time.sleep(3)
    wevtutil = "wevtutil.exe"

    for log in ["security", "application", "system"]:
        common.execute([wevtutil, "cl", log])


if __name__ == "__main__":
    exit(main())
