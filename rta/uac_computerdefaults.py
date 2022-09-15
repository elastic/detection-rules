# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="7cc740ff-2e6c-4740-9323-46dcbb4dbfbc",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "UAC Bypass via ComputerDefaults Execution Hijack",
            "rule_id": "7c0048d5-356d-4f69-839e-10c1e194958f",
        }
    ],
    siem=[],
    techniques=["T1548"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    key = "Software\\Classes\\ms-settings\\shell\\open\\command"
    value = "test"
    data = "test"

    with common.temporary_reg(common.HKCU, key, value, data):
        pass

    computerdefaults = "C:\\Users\\Public\\ComputerDefaults.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    common.copy_file(EXE_FILE, computerdefaults)

    common.execute([computerdefaults, "/c", powershell], timeout=2, kill=True)
    common.remove_file(computerdefaults)


if __name__ == "__main__":
    exit(main())
