# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="b8dcb997-e099-472e-8f2f-15a80c8dfe1a",
    platforms=["windows"],
    endpoint=[
        {
            'rule_id': 'dec8781c-ef73-4037-9684-ef28c0322fa4',
            'rule_name': 'Script File Written to Startup Folder'
        },
        {
            "rule_name": "Unusual File Written or Modified in Startup Folder",
            "rule_id": "30a90136-7831-41c3-a2aa-1a303c1186ac",
        }
    ],
    siem=[],
    techniques=['T1547', 'T1547.001'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    proc = "C:\\Users\\Public\\proc.exe"
    path = "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Windows\\'Start Menu'\\Programs\\Startup\\"
    file = path + "\\a.js"
    common.copy_file(EXE_FILE, proc)
    Path(path).mkdir(parents=True, exist_ok=True)

    common.execute([proc, "/c", f"Copy-Item {EXE_FILE} {file}"], timeout=10)
    common.remove_files(proc, file)


if __name__ == "__main__":
    exit(main())
