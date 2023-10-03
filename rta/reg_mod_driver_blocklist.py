# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="cd2154fa-de1a-4098-83c1-be1ab23da379",
    platforms=["windows"],
    endpoint=[
        {
            'rule_id': '31b7218e-ba98-4228-a39a-d0e0d1c0e5b7',
            'rule_name': 'Attempt to Disable Windows Driver Blocklist via Registry'
        }
    ],
    siem=[],
    techniques=['T1112'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    key = "SYSTEM\\CurrentControlSet\\Control\\CI\\Config"
    value = "VulnerableDriverBlocklistEnable"
    data = 0

    with common.temporary_reg(common.HKLM, key, value, data, data_type="dword"):
        pass


if __name__ == "__main__":
    exit(main())
