# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="3791a2d2-473a-45a0-b776-a398f4602bcd",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '2e1e835d-01e5-48ca-b9fc-7a61f7f11902', 'rule_name': 'Renamed AutoIt Scripts Interpreter'}],
    techniques=[""],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(metadata.platforms)
def main():
    autoit = "C:\\Users\\Public\\rta.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(RENAMER, rcedit)
    common.copy_file(EXE_FILE, autoit)

    common.log("Modifying the OriginalFileName attribute")
    common.execute([rcedit, autoit, "--set-version-string", "OriginalFilename", "autoit.exe"])

    common.execute([autoit], timeout=2, kill=True)

    common.remove_files(rcedit, autoit)


if __name__ == "__main__":
    exit(main())
