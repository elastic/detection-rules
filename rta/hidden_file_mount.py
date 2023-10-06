# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path
from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="1d7ff305-03b5-4917-b32c-d0267018063c",
    platforms=["macos"],
    endpoint=[
        {"rule_name": "MacOS Hidden File Mounted", "rule_id": "c5f219ca-4bda-461b-bc54-246c0bb48143"},
    ],
    siem=[],
    techniques=["T1211", "T1059", "T1059.004"],
)


@common.requires_os(*metadata.platforms)
def main():

    mount_dir = "/tmp/.exploit"
    disk_file = "disk.dmg"

    # create disk image
    common.execute(["hdiutil", "create", "-size", "50b", "-volname", ".exploit", "-ov", disk_file], kill=True)

    # attach disk image to mount point
    common.log("Launching hdutil commands to mount dummy dmg")
    common.execute(["hdiutil", "attach", "-mountpoint", mount_dir, disk_file], kill=True)

    # cleanup
    common.execute(["hdiutil", "eject", "/tmp/.exploit"], timeout=10, kill=True)
    common.remove_file(disk_file)


if __name__ == "__main__":
    exit(main())
