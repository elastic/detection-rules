# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="e70ab2f3-7a67-4cd8-9969-ad4ebe0358bc",
    platforms=["windows"],
    endpoint=[],
    siem=[
        {
            'rule_id': 'fe794edd-487f-4a90-b285-3ee54f2af2d3',
            'rule_name': 'Microsoft Windows Defender Tampering'
        },
        {
            'rule_id': '2ffa1f1e-b6db-47fa-994b-1512743847eb',
            'rule_name': 'Windows Defender Disabled via Registry Modification'
        }
    ],
    techniques=['T1562', 'T1562.001', 'T1562.006'],
)


@common.requires_os(*metadata.platforms)
def main():
    key = "SOFTWARE\\Policies\\Microsoft\\Windows Defender"
    value = "DisableAntiSpyware"
    data = 1

    with common.temporary_reg(common.HKLM, key, value, data, data_type="dword"):
        pass


if __name__ == "__main__":
    exit(main())
