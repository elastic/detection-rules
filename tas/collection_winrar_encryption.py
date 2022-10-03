# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="2be84b3c-9aee-4e4b-ad8f-cf29334a9577",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '45d273fb-1dca-457d-9855-bcb302180c21', 'rule_name': 'Encrypting Files with WinRar or 7z'}],
    techniques=[""],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    rar = "C:\\Users\\Public\\rar.exe"
    common.copy_file(EXE_FILE, rar)

    # Execute command
    common.execute([rar, "/c", "echo", "a", "-hp"], timeout=10)
    common.remove_file(rar)


if __name__ == "__main__":
    exit(main())
