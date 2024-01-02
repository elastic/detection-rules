# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="6a884a9a-b061-4eeb-8711-f14f6b49c9c0",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': 'd31f183a-e5b1-451b-8534-ba62bca0b404',
        'rule_name': 'Disabling User Account Control via Registry Modification'
    }],
    techniques=['T1548', 'T1548.002', 'T1548', 'T1548.002'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    value = "EnableLUA"
    data = 0

    with common.temporary_reg(common.HKLM, key, value, data, data_type="dword"):
        pass


if __name__ == "__main__":
    exit(main())
