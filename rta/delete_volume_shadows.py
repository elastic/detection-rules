# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Volume Shadow Copy Deletion with vssadmin and wmic
# RTA: delete_volume_shadow.py
# signal.rule.name: Volume Shadow Copy Deletion via VssAdmin
# ELastic Detection: Volume Shadow Copy Deletion via WMIC
# ATT&CK: T1107
# Description: Uses both vssadmin.exe and wmic.exe to delete volume shadow copies.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="ae6343cc-3b56-4f60-854f-7102db519ec4",
    platforms=["windows"],
    endpoint=[],
    siem=[{"rule_id": "dc9c1f74-dac3-48e3-b47f-eb79db358f57", "rule_name": "Volume Shadow Copy Deletion via WMIC"}],
    techniques=["T1490"],
)


@common.requires_os(metadata.platforms)
def main():
    common.log("Deleting volume shadow copies...")
    common.execute(["vssadmin.exe", "delete", "shadows", "/for=c:", "/oldest", "/quiet"])
    # Create a volume shadow copy so that there is at least one to delete
    common.execute(["wmic.exe", "shadowcopy", "call", "create", "volume=c:\\"])
    common.execute(["wmic.exe", "shadowcopy", "delete", "/nointeractive"])


if __name__ == "__main__":
    exit(main())
