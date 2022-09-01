# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Export Registry Hives
# RTA: registry_hive_export.py
# ATT&CK: TBD
# Description: Exports the SAM, SECURITY and SYSTEM hives - useful in credential harvesting and discovery attacks.

import os

from . import common

PLATFORMS = [common.WINDOWS]
TRIGGERED_RULES = {
    "SIEM": [
        {
            "rule_id": "a7e7bfa3-088e-4f13-b29e-3986e0e756b8",
            "rule_name": "Credential Acquisition via Registry Hive Dumping",
        }
    ],
    "ENDPOINT": [],
}
TECHNIQUES = ["T1003"]
RTA_ID = "dfdcc4f4-5aca-486a-8115-b15b653b9b4f"

REG = "reg.exe"


@common.requires_os(PLATFORMS)
def main():
    for hive in ["sam", "security", "system"]:
        filename = os.path.abspath("%s.reg" % hive)
        common.log("Exporting %s hive to %s" % (hive, filename))
        common.execute([REG, "save", "hkey_local_machine\\%s" % hive, filename])
        common.remove_file(filename)

        common.execute([REG, "save", "hklm\\%s" % hive, filename])
        common.remove_file(filename)


if __name__ == "__main__":
    exit(main())
