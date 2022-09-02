# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Adobe Hijack Persistence
# RTA: adobe_hijack.py
# ATT&CK: T1044
# Description: Replaces PE file that will run on Adobe Reader start.

import os

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="2df08481-31db-44a8-b01d-1c0df827bddb",
    platforms=["windows"],
    endpoint=[],
    siem=[{"rule_id": "2bf78aa2-9c56-48de-b139-f169bf99cf86", "rule_name": "Adobe Hijack Persistence"}],
    techniques=["T1574"],
)


@common.requires_os(metadata.platforms)
def main():
    rdr_cef_dir = "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF"
    rdrcef_exe = os.path.join(rdr_cef_dir, "RdrCEF.exe")
    cmd_path = "C:\\Windows\\System32\\cmd.exe"
    backup = os.path.abspath("xxxxxx")
    backedup = False

    # backup original if it exists
    if os.path.isfile(rdrcef_exe):
        common.log("{} already exists, backing up file.".format(rdrcef_exe))
        common.copy_file(rdrcef_exe, backup)
        backedup = True
    else:
        common.log("{} doesn't exist. Creating path.".format(rdrcef_exe))
        os.makedirs(rdr_cef_dir)

    # overwrite original
    common.copy_file(cmd_path, rdrcef_exe)

    # cleanup
    if backedup:
        common.log("Putting back backup copy.")
        common.copy_file(backup, rdrcef_exe)
        os.remove(backup)
    else:
        common.remove_file(rdrcef_exe)
        os.removedirs(rdr_cef_dir)


if __name__ == "__main__":
    exit(main())
