# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="2edd7889-578b-4870-befd-6b3d0f5a10fd",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'a22a09c2-2162-4df0-a356-9aacbeb56a04', 'rule_name': 'DNS-over-HTTPS Enabled via Registry'}],
    techniques=['T1562'],
)


@common.requires_os(*metadata.platforms)
def main():
    key = "SOFTWARE\\Policies\\Microsoft\\Edge"
    value = "BuiltInDnsClientEnabled"
    data = 1

    with common.temporary_reg(common.HKLM, key, value, data, data_type="dword"):
        pass


if __name__ == "__main__":
    exit(main())
