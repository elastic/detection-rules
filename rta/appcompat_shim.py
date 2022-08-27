# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Application Compatibility Shims
# RTA: appcompat_shim.py
# ATT&CK: T1138
# Description: Use sdbinst.exe to install a binary patch/application shim.

import time

from . import common

PLATFORMS = [common.WINDOWS]
TRIGGERED_RULES = {
    "SIEM": [
        {
            "rule_id": "fd4a992d-6130-4802-9ff8-829b89ae801f",
            "rule_name": "Potential Application Shimming via Sdbinst",
        }
    ],
    "ENDPOINT": [],
}
TACTICS = ["TA0003","TA0004"]
RTA_ID = "a4a8608e-d94f-4eb1-b500-738328307bbc"

SHIM_FILE = common.get_path("bin", "CVE-2013-3893.sdb")


@common.requires_os(PLATFORMS)
@common.dependencies(SHIM_FILE)
def main():
    common.log("Application Compatibility Shims")

    common.execute(["sdbinst.exe", "-q", "-p", SHIM_FILE])
    time.sleep(2)

    common.log("Removing installed shim", log_type="-")
    common.execute(["sdbinst.exe", "-u", SHIM_FILE])


if __name__ == "__main__":
    exit(main())
