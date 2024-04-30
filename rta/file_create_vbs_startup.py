# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="7cee9313-5e55-472b-9d61-a95b0c9725d6",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': 'f7c4dc5a-a58d-491d-9f14-9b66507121c0',
        'rule_name': 'Persistent Scripts in the Startup Directory'
    }],
    techniques=['T1547', 'T1547.001'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    path = "C:\\Users\\Programs\\Startup"
    Path(path).mkdir(parents=True, exist_ok=True)
    file = path + "\\a.vbs"
    common.copy_file(EXE_FILE, file)

    common.remove_files(file)


if __name__ == "__main__":
    exit(main())
