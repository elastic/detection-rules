# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Adobe Hijack Persistence
# ATT&CK: T1044
# Description: Replaces PE file that will run on Adobe Reader start.

import sys
from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="2df08481-31db-44a8-b01d-1c0df827bddb",
    platforms=["windows"],
    endpoint=[],
    siem=[{"rule_id": "2bf78aa2-9c56-48de-b139-f169bf99cf86", "rule_name": "Adobe Hijack Persistence"}],
    techniques=["T1574"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    rdr_cef_dir = Path("C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF")
    rdrcef_exe = rdr_cef_dir / "RdrCEF.exe"
    cmd_path = "C:\\Windows\\System32\\cmd.exe"
    backup = Path("xxxxxx").resolve()
    backedup = False

    # backup original if it exists
    if rdrcef_exe.is_file():
        common.log(f"{rdrcef_exe} already exists, backing up file.")
        common.copy_file(rdrcef_exe, backup)
        backedup = True
    else:
        common.log(f"{rdrcef_exe} doesn't exist. Creating path.")
        rdr_cef_dir.mkdir(parents=True)

    # overwrite original
    common.copy_file(cmd_path, rdrcef_exe)

    # cleanup
    if backedup:
        common.log("Putting back backup copy.")
        common.copy_file(backup, rdrcef_exe)
        backup.unlink()
    else:
        common.remove_file(rdrcef_exe)
        rdr_cef_dir.rmdir()


if __name__ == "__main__":
    sys.exit(main())
