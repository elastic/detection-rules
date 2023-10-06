# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="3b8454af-db6b-4d4c-92c6-89ca7b6640f1",
    platforms=["windows"],
    endpoint=[{
        'rule_id': 'adaf95d2-28ce-4880-af16-f3041b624440',
        'rule_name': 'UAC Bypass Attempt via Windows Directory Masquerading'
    }],
    siem=[],
    techniques=['T1548', 'T1548.002'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    proc = "C:\\Users\\Public\\proc.exe"
    common.copy_file(EXE_FILE, proc)

    common.execute([proc, "/c", "echo", "C:\\Windows \\System32\\a.exe"], timeout=5, kill=True)
    common.remove_files(proc)


if __name__ == "__main__":
    exit(main())
