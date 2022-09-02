# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="d3c0c965-3167-4fe3-8aee-a9f101766b5a",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Unusual Remote Desktop Client Process", "rule_id": "d448566e-486f-4b61-a76f-945662313d49"}
    ],
    siem=[],
    techniques=["T1021"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")


@common.requires_os(metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    posh = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\posh.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\mstscax.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    common.copy_file(user32, dll)
    common.copy_file(powershell, posh)
    common.copy_file(PS1_FILE, ps1)

    common.log("Loading mstscax.dll into posh")
    common.execute(
        [
            posh,
            "-c",
            f"Import-Module {ps1}; Invoke-ImageLoad {dll};",
            "Test-NetConnection",
            "-ComputerName",
            "portquiz.net",
            "-Port",
            "3389",
        ],
        timeout=10,
    )
    common.remove_files(dll, ps1, posh)


if __name__ == "__main__":
    exit(main())
