# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="2bb1016f-b3e9-455d-b665-02a0aafc797a",
    platforms=["windows"],
    endpoint=[{
        'rule_id': 'ff5fd85a-e770-4e57-8bae-0d267442eb9f',
        'rule_name': 'Suspicious Image File Execution Options Modification'
    }],
    siem=[],
    techniques=['T1546', 'T1546.012'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    common.log("Temp Registry mod: IFEO")

    key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\rta.exe\\"
    value = "Debugger"
    data = "Test"

    with common.temporary_reg(common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
