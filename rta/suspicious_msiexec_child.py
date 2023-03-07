# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="2cefb7c2-5ffc-4410-a63c-bded93b258c3",
    platforms=["windows"],
    endpoint=[{
        'rule_id': '877c6bd9-8df1-4a15-aa97-2a091731b15d',
        'rule_name': 'Suspicious MsiExec Child Process'
    }],
    siem=[],
    techniques=['T1218', 'T1218.007'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    msiexec = "C:\\Users\\Public\\msiexec.exe"
    regsvr32 = "C:\\Users\\Public\\regsvr32.exe"
    common.copy_file(EXE_FILE, msiexec)
    common.copy_file(EXE_FILE, regsvr32)

    common.execute([msiexec, "/c", regsvr32, "echo", "scrobj.dll"], timeout=5, kill=True)
    common.remove_files(msiexec)


if __name__ == "__main__":
    exit(main())
