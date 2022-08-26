# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Windows Core Process Masquerade
# RTA: process_name_masquerade.py
# signal.rule.name: Unusual Parent-Child Relationship
# ATT&CK: T1036
# Description: Creates several processes which mimic core Windows process names but that are not those executables.

import os

from . import common

PLATFORMS = [common.WINDOWS]
TRIGGERED_RULES = {
    "SIEM": [{"rule_id": "35df0dd8-092d-4a83-88c1-5151a804f31b", "rule_name": "Unusual Parent-Child Relationship"}],
    "ENDPOINT": []
}
TACTICS = []
RTA_ID = "ead01ef7-73da-4990-bce3-cef13f8aaca4"

MY_APP = common.get_path("bin", "myapp.exe")


@common.requires_os(PLATFORMS)
@common.dependencies(MY_APP)
def main():
    masquerades = [
        "svchost.exe",
        "lsass.exe",
        "services.exe",
        "csrss.exe",
        "smss.exe",
        "wininit.exe",
        "explorer.exe",
    ]

    for name in masquerades:
        path = os.path.abspath(name)
        common.copy_file(MY_APP, path)
        common.execute(path, timeout=3, kill=True)
        common.remove_file(path)


if __name__ == "__main__":
    exit(main())
