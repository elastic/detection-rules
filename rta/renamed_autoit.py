# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="43636c0c-162b-4445-bcd0-348cbd203fa3",
    platforms=["windows"],
    endpoint=[{"rule_name": "Renamed AutoIt Scripts Interpreter", "rule_id": "99f2327e-871f-4b8a-ae75-d1c4697aefe4"}],
    siem=[],
    techniques=["T1036"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(metadata.platforms)
def main():
    autoit = "C:\\Users\\Public\\rta.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"

    common.copy_file(RENAMER, rcedit)
    common.copy_file(EXE_FILE, autoit)

    # Execute command
    common.log("Modifying the OriginalFileName attribute")
    common.execute(
        [rcedit, autoit, "--set-version-string", "OriginalFileName", "autoitrta.exe"],
        timeout=10,
    )
    common.execute([autoit], timeout=5, kill=True)

    common.remove_files(autoit, rcedit)


if __name__ == "__main__":
    exit(main())
