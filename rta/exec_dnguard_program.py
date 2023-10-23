# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="db2e6589-d2df-4d9d-9d88-d91af5fd57e9",
    platforms=["windows"],
    endpoint=[{
        'rule_id': 'e691d379-6d01-43cc-9f1e-ab10df48a6bc',
        'rule_name': 'Execution of a DNGUard Protected Program'
    }],
    siem=[],
    techniques=['T1027', 'T1027.002'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")


@common.requires_os(*metadata.platforms)
def main():
    posh = "C:\\Users\\Public\\posh.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\HVMRuntm.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    common.copy_file(EXE_FILE, posh)
    common.copy_file(user32, dll)
    common.copy_file(PS1_FILE, ps1)

    # Execute command

    common.log("Loading DNGUard DLL")
    common.execute([posh, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)

    common.remove_files(posh, dll, ps1)


if __name__ == "__main__":
    exit(main())
