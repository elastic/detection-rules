# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="8896c6ac-ead6-4f4e-aecf-8308fd53e78c",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '3535c8bb-3bd5-40f4-ae32-b7cd589d5372', 'rule_name': 'Port Forwarding Rule Addition'}],
    techniques=['T1572'],
)


@common.requires_os(*metadata.platforms)
def main():
    key = "System\\CurrentControlSet\\Services\\PortProxy\\v4tov4"
    value = "a"
    data = "0"

    with common.temporary_reg(common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
