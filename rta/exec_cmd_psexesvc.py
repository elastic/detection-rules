# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="7c4e0d1e-e80a-465a-9612-a319800390f4",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': 'e2f9fdf5-8076-45ad-9427-41e0e03dc9c2',
        'rule_name': 'Suspicious Process Execution via Renamed PsExec Executable'
    }],
    techniques=['T1569', 'T1569.002'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(*metadata.platforms)
def main():
    psexesvc = "C:\\Users\\Public\\rta.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(RENAMER, rcedit)
    common.copy_file(EXE_FILE, psexesvc)

    common.log("Modifying the OriginalFileName attribute")
    common.execute([rcedit, psexesvc, "--set-version-string", "OriginalFilename", "psexesvc.exe"])

    common.execute([psexesvc], timeout=2, kill=True)

    common.remove_files(rcedit, psexesvc)


if __name__ == "__main__":
    exit(main())
