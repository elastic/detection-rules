# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="735969b3-6a2e-4c7d-b18a-59e2f36ef13b",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'c5ce48a6-7f57-4ee8-9313-3d0024caee10', 'rule_name': 'Installation of Custom Shim Databases'}],
    techniques=['T1546', 'T1546.011'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom"
    value = "a.sdb"
    data = "RTA"

    with common.temporary_reg(common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
