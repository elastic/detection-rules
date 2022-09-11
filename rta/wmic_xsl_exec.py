# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="b9d5427a-33c4-4b1d-838d-f47c5f3b0b43",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
        {"rule_name": "Suspicious WMIC XSL Script Execution", "rule_id": "18371ec4-ee2f-465b-8757-ee726914006c"},
    ],
    siem=[],
    techniques=["T1220", "T1047", "T1036"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")


@common.requires_os(metadata.platforms)
def main():
    wmic = "C:\\Users\\Public\\wmic.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\jscript.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    common.copy_file(EXE_FILE, wmic)
    common.copy_file(user32, dll)
    common.copy_file(PS1_FILE, ps1)

    common.log("Loading jscript.dll into fake wmic")
    common.execute(
        [wmic, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}; echo /format:"],
        timeout=10,
    )

    common.remove_files(wmic, dll, ps1)


if __name__ == "__main__":
    exit(main())
