# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="32462f3e-d5af-4ef9-8260-aa9fbeb6e117",
    platforms=["windows"],
    endpoint=[
        {
            'rule_id': '2ffc3943-8100-4f77-9c8f-e8f9e185604b',
            'rule_name': 'Persistence via AutodialDLL Registry Modification'
        }
    ],
    siem=[],
    techniques=['T1112'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    key = "SYSTEM\\ControlSet001\\Services\\WinSock2\\Parameters"
    value = "AutodialDLL"
    data = "RTA"

    with common.temporary_reg(common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
