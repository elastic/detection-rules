# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="d87a9024-5e8e-44c2-b943-0680f92ad995",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '8f3e91c7-d791-4704-80a1-42c160d7aa27',
        'rule_name': 'Potential Port Monitor or Print Processor Registration Abuse'
    }],
    techniques=['T1547', 'T1547.010', 'T1547', 'T1547.010'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    key = "SYSTEM\\ControlSet001\\Control\\Print\\Monitors"
    value = "RTA"
    data = "RTA.dll"

    with common.temporary_reg(common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
