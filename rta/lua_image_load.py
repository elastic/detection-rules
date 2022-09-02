# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="860e5968-c31f-4928-ac05-3c3c2d19450c",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Suspicious Windows LUA Script Execution", "rule_id": "8f237d98-1825-4c27-a5cd-e38bde70882a"}
    ],
    siem=[],
    techniques=["T1036"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(metadata.platforms)
def main():
    posh = "C:\\Users\\Public\\posh.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\luacom.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(EXE_FILE, posh)
    common.copy_file(user32, dll)
    common.copy_file(PS1_FILE, ps1)
    common.copy_file(RENAMER, rcedit)

    # Modify the originalfilename to invalidate the code sig
    common.log("Modifying the OriginalFileName attribute")
    common.execute([rcedit, dll, "--set-version-string", "OriginalFilename", "unsigned.exe"])

    common.log("Loading luacom.dll into fake posh")
    common.execute(
        [
            posh,
            "-c",
            f"Import-Module {ps1}; Invoke-ImageLoad {dll};",
            "Test-NetConnection",
            "-ComputerName",
            "portquiz.net",
            "-Port",
            "445",
        ],
        timeout=10,
    )

    common.remove_files(posh, dll, ps1, rcedit)


if __name__ == "__main__":
    exit(main())
