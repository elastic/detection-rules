# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Abusing SettingContent-ms Files
# RTA: settingcontentms_files.py
# signal.rule.name: Potential Modification of Accessibility Binaries
# signal.rule.name: Local Service Commands
# ATT&CK: T1193, T1204, T1064
# Description: SettingContent-ms file written to specific path or by risky process

import time

from . import common

PLATFORMS = [common.WINDOWS]
TRIGGERED_RULES = {
    "SIEM": [
        {
            "rule_id": "7405ddf1-6c8e-41ce-818f-48bea6bcaed8",
            "rule_name": "Potential Modification of Accessibility Binaries",
        }
    ],
    "ENDPOINT": [],
}
TECHNIQUES = ["T1546"]
RTA_ID = "7dea9748-dcac-49a9-8909-bd1f5590e508"


@common.requires_os(PLATFORMS)
def main():
    # Write to AppData\Local\
    common.execute(
        ["cmd", "/c", "echo", "test", ">", "%APPDATA%\\test.SettingContent-ms"]
    )
    time.sleep(1)
    common.execute(["cmd", "/c", "del", "%APPDATA%\\test.SettingContent-ms"])


if __name__ == "__main__":
    exit(main())
