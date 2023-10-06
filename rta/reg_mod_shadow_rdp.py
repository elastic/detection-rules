# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="a6263f00-58b4-4555-b88f-9d66a7395891",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': 'c57f8579-e2a5-4804-847f-f2732edc5156',
        'rule_name': 'Potential Remote Desktop Shadowing Activity'
    }],
    techniques=['T1021'],
)


@common.requires_os(*metadata.platforms)
def main():
    common.log("Modifying RDP Shadow reg key...")

    key = "Software\\Policies\\Microsoft\\Windows NT\\Terminal Services"
    value = "Shadow"
    data = "Test"

    with common.temporary_reg(common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
