# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="97979b30-908d-4c57-a33a-f3b78e55a84a",
    platforms=["windows"],
    endpoint=[{
        'rule_id': 'aaa80718-1ed9-43bd-bcf7-97f2a6c93ea8',
        'rule_name': 'Persistence via Microsoft Office AddIns'
    }],
    siem=[],
    techniques=['T1137'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    path = "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Word\\Startup"
    Path(path).mkdir(parents=True, exist_ok=True)
    file = path + "\\file.exe"

    common.copy_file(EXE_FILE, file)
    common.remove_file(file)


if __name__ == "__main__":
    exit(main())
