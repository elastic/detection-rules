# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="456ec321-41c8-4a41-8f6f-40b8e3d1c295",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Suspicious MS Office Execution via DCOM", "rule_id": "6a714747-2671-4523-b233-744f119949b6"}
    ],
    siem=[],
    techniques=["T1112", "T1566"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    winword = "C:\\Users\\Public\\winword.exe"
    common.copy_file(EXE_FILE, winword)

    key = "SOFTWARE\\Microsoft\\Office\\Test\\Security"
    value = "AccessVBOM"
    data = "1"

    with common.temporary_reg(common.HKCU, key, value, data):
        pass
    common.execute([winword, "-c", "echo", "-Embedding", ";powershell"], timeout=5, kill=True)
    common.remove_file(winword)


if __name__ == "__main__":
    exit(main())
