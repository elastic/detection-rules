# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="2cd02bee-6774-4b93-a632-995462440371",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': 'b64b183e-1a76-422d-9179-7b389513e74d',
        'rule_name': 'Windows Script Interpreter Executing Process via WMI'
    }],
    techniques=['T1566', 'T1566.001'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")
PS1_FILE = common.get_path("bin", "Invoke-ImageLoad.ps1")


@common.requires_os(*metadata.platforms)
def main():
    cscript = "C:\\Users\\Public\\cscript.exe"
    user32 = "C:\\Windows\\System32\\user32.dll"
    dll = "C:\\Users\\Public\\wmiutils.dll"
    ps1 = "C:\\Users\\Public\\Invoke-ImageLoad.ps1"
    wmiprvse = "C:\\Users\\Public\\WmiPrvSE.exe"
    common.copy_file(EXE_FILE, cscript)
    common.copy_file(user32, dll)
    common.copy_file(PS1_FILE, ps1)
    common.copy_file(EXE_FILE, wmiprvse)

    common.log("Loading wmiutils.dll into fake cscript")
    common.execute([cscript, "-c", f"Import-Module {ps1}; Invoke-ImageLoad {dll}"], timeout=10)
    common.execute([wmiprvse, "/c", cscript], timeout=1, kill=True)
    common.remove_files(cscript, dll, ps1)


if __name__ == "__main__":
    exit(main())
