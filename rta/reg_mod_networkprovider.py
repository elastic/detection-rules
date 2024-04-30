# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="1b4050d9-e3fa-4559-b188-522b620584c8",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '54c3d186-0461-4dc3-9b33-2dc5c7473936',
        'rule_name': 'Network Logon Provider Registry Modification'
    }],
    techniques=['T1556', 'T1543'],
)


@common.requires_os(*metadata.platforms)
def main():
    key = "System\\CurrentControlSet\\Services\\Test\\NetworkProvider"
    value = "ProviderPath"
    data = "C:\\Nonexistent.exe"

    with common.temporary_reg(common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
