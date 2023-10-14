# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="5432792c-d31a-42cc-a82f-0884ea230493",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'f44fa4b6-524c-4e87-8d9e-a32599e4fb7c', 'rule_name': 'Persistence via Microsoft Office AddIns'}],
    techniques=['T1137'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    path = "C:\\Users\\Public\\\\AppData\\Roaming\\Microsoft\\Word\\Startup"
    Path(path).mkdir(parents=True, exist_ok=True)
    file = path + "\\file.xll"
    common.copy_file(EXE_FILE, file)

    common.remove_files(file)


if __name__ == "__main__":
    exit(main())
