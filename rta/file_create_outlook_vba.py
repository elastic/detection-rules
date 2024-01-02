# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="3c40b5fd-afd0-4794-8af3-f7af249edf84",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '397945f3-d39a-4e6f-8bcb-9656c2031438', 'rule_name': 'Persistence via Microsoft Outlook VBA'}],
    techniques=['T1137'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    path = "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Outlook"
    Path(path).mkdir(parents=True, exist_ok=True)
    file = path + "\\VbaProject.OTM"
    common.copy_file(EXE_FILE, file)

    common.remove_files(file)


if __name__ == "__main__":
    exit(main())
