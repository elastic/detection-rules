# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="eb06a33e-bc80-412b-8ae8-f45af6682293",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '71c5cb27-eca5-4151-bb47-64bc3f883270', 'rule_name': 'Suspicious RDP ActiveX Client Loaded'}],
    techniques=['T1021'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")


@common.requires_os(*metadata.platforms)
def main():
    proc = "C:\\Users\\Public\\proc.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\mstscax.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    wmiprvse = "C:\\Users\\Public\\WmiPrvSE.exe"
    common.copy_file(EXE_FILE, proc)
    common.copy_file(user32, dll)
    common.copy_file(PS1_FILE, ps1)
    common.copy_file(EXE_FILE, wmiprvse)

    common.log("Loading mstscax.dll into proc")
    common.execute([proc, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)
    common.remove_files(proc, dll, ps1)


if __name__ == "__main__":
    exit(main())
