# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="64a7cd38-767f-4d46-9350-feb585a32c18",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Unusual DLL Extension Loaded by Rundll32 or Regsvr32",
            "rule_id": "76da5dca-ffe5-4756-85ba-3ac2e6ccf623",
        },
        {"rule_name": "Execution from Unusual Directory", "rule_id": "16c84e67-e5e7-44ff-aefa-4d771bcafc0c"},
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
    ],
    siem=[],
    techniques=["T1218", "T1036", "T1059"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")


@common.requires_os(metadata.platforms)
def main():
    rundll32 = "C:\\Users\\Public\\rundll32.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\a.rta"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    common.copy_file(EXE_FILE, rundll32)
    common.copy_file(user32, dll)
    common.copy_file(PS1_FILE, ps1)

    # Execute command

    common.log("Loading a.rta into fake rundll32")
    common.execute([rundll32, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)

    common.remove_files(rundll32, dll, ps1)


if __name__ == "__main__":
    exit(main())
