# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Enable RDP Through Registry
# RTA: registry_rdp_enable.py
# signal.rule.name: Potential Modification of Accessibility Binaries
# ATT&CK: T1076
# Description: Identifies registry write modification to enable RDP access.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="1ef2a173-a9c8-446d-9d56-f7e54a197a33",
    platforms=["windows"],
    endpoint=[],
    siem=[
        {'rule_id': '58aa72ca-d968-4f34-b9f7-bea51d75eb50', 'rule_name': 'RDP Enabled via Registry'}
    ],
    techniques=['T1021', 'T1021.001'],
)


@common.requires_os(*metadata.platforms)
def main():
    common.log("Enabling RDP Through Registry")

    # get the current value
    key = "System\\CurrentControlSet\\Control\\Terminal Server"
    value = "fDenyTSConnections"

    with common.temporary_reg(common.HKLM, key, value, 0, common.DWORD):
        pass


if __name__ == "__main__":
    exit(main())
