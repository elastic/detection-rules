# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="42eed432-af05-45d3-b788-7e3220f81f9a",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Suspicious ImageLoad via Windows Update Auto Update Client",
            "rule_id": "3788c03d-28a5-4466-b157-d6dd4dc449bb",
        }
    ],
    siem=[],
    techniques=["T1218"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(metadata.platforms)
def main():
    wuauclt = "C:\\Users\\Public\\wuauclt.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\unsigned.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(EXE_FILE, wuauclt)
    common.copy_file(user32, dll)
    common.copy_file(PS1_FILE, ps1)
    common.copy_file(RENAMER, rcedit)

    # Modify the originalfilename to invalidate the code sig
    common.log("Modifying the OriginalFileName attribute")
    common.execute([rcedit, dll, "--set-version-string", "OriginalFilename", "unsigned.exe"])

    common.log("Loading unsigned.dll into fake wuauclt")
    common.execute(
        [
            wuauclt,
            "-c",
            f"Import-Module {ps1}; Invoke-ImageLoad {dll}",
            ";echo",
            "/RunHandlerComServer",
            ";echo",
            "/UpdateDeploymentProvider",
        ],
        timeout=10,
    )

    common.remove_files(wuauclt, dll, ps1, rcedit)


if __name__ == "__main__":
    exit(main())
