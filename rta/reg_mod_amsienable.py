# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="78715019-6eff-45b1-a942-47db87d55b01",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'f874315d-5188-4b4a-8521-d1c73093a7e4', 'rule_name': 'Modification of AmsiEnable Registry Key'}],
    techniques=['T1562', 'T1562.001'],
)


@common.requires_os(*metadata.platforms)
def main():
    key = "Software\\Microsoft\\Windows Script\\Settings"
    value = "AmsiEnable"
    data = 0

    with common.temporary_reg(common.HKCU, key, value, data, data_type="dword"):
        pass


if __name__ == "__main__":
    exit(main())
