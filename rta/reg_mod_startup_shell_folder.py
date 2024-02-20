# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="16fe008f-58b5-4a8c-9e73-2784edf636b1",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': 'c8b150f0-0164-475b-a75e-74b47800a9ff',
        'rule_name': 'Suspicious Startup Shell Folder Modification'
    }],
    techniques=['T1547', 'T1547.001'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    key = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
    value = "Common Startup"
    uvalue = "Startup"
    data = "Test"

    with common.temporary_reg(common.HKLM, key, value, data):
        pass
    with common.temporary_reg(common.HKCU, key, uvalue, data):
        pass


if __name__ == "__main__":
    exit(main())
