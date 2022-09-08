# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="c4eefb59-2c59-4904-a04e-5e3a75f54a46",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Shadow Copy Service Disabled via Registry Modification",
            "rule_id": "b2409cd4-3b23-4b2d-82e4-bbb25594999a",
        },
        {
            "rule_name": "VSS Service Disabled Followed by a Suspicious File Rename",
            "rule_id": "d6cde651-adc9-4074-b167-65e6b82116b4",
        },
        {
            "rule_name": "Suspicious File Rename by an Unusual Process",
            "rule_id": "df874d7e-6639-44ce-b47d-96254022ccd5",
        },
    ],
    siem=[],
    techniques=["T1218", "T1112", "T1486", "T1490", "T1059"],
)

HIGHENTROPY = common.get_path("bin", "highentropy.txt")


@common.requires_os(metadata.platforms)
def main():
    key = "SYSTEM\\CurrentControlSet\\Services\\VSS"
    value = "Start"
    data = 4

    with common.temporary_reg(common.HKLM, key, value, data, data_type="dword"):
        pass

    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    jpg = "C:\\Users\\Public\\jpg.jpg"
    jpgenc = "C:\\Users\\Public\\jpg.enc"
    # Creating a high entropy file, and executing the rename operation
    common.copy_file(HIGHENTROPY, jpg)
    common.execute([powershell, "/c", f"Rename-Item {jpg} {jpgenc}"], timeout=10)
    common.execute([powershell, "/c", "Remove-Item 'C:\\Users\\Public\\*jpg*' -Force"], timeout=10)


if __name__ == "__main__":
    exit(main())
