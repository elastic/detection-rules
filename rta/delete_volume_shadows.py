# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Name: Volume Shadow Copy Deletion with vssadmin and wmic
# RTA: delete_volume_shadow.py
# signal.rule.name: Volume Shadow Copy Deletion via VssAdmin
# ELastic Detection: Volume Shadow Copy Deletion via WMIC
# ATT&CK: T1107
# Description: Uses both vssadmin.exe and wmic.exe to delete volumne shadow copies.

from . import common


@common.requires_os(common.WINDOWS)
def main():
    common.log("Deleting volume shadow copies...")
    common.execute(["vssadmin.exe", "delete", "shadows", "/for=c:", "/oldest", "/quiet"])
    # Create a volume shadow copy so that there is at least one to delete
    common.execute(["wmic.exe", "shadowcopy", "call", "create", "volume=c:\\"])
    common.execute(["wmic.exe", "shadowcopy", "delete", "/nointeractive"])


if __name__ == "__main__":
    exit(main())
