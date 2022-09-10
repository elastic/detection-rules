# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="d2671cc5-87d0-4612-9e3c-0862b137d242",
    platforms=["windows"],
    endpoint=[{"rule_name": "WMI Image Load via Microsoft Office", "rule_id": "46952f58-6741-4280-8e74-fa43f63c9604"}],
    siem=[],
    techniques=["T1047", "T1566"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")


@common.requires_os(metadata.platforms)
def main():
    winword = "C:\\Users\\Public\\winword.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\wmiutils.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    wmiprvse = "C:\\Users\\Public\\WmiPrvSE.exe"
    common.copy_file(EXE_FILE, winword)
    common.copy_file(user32, dll)
    common.copy_file(PS1_FILE, ps1)
    common.copy_file(EXE_FILE, wmiprvse)

    common.log("Loading wmiutils.dll into fake winword")
    common.execute([winword, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)
    common.execute([wmiprvse, "/c", "powershell"], timeout=1, kill=True)
    common.remove_files(winword, dll, ps1)


if __name__ == "__main__":
    exit(main())
