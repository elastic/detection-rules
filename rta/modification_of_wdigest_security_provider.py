# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="878ffa93-dea6-48f8-9441-e199bc23ec6b",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'd703a5af-d5b0-43bd-8ddb-7a5d500b7da5', 'rule_name': 'Modification of WDigest Security Provider'}],
    techniques=["T1003"],
)


@common.requires_os(*metadata.platforms)
def main():
    key = "System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"
    value = "UseLogonCredential"
    data = 1

    with common.temporary_reg(common.HKLM, key, value, data, data_type="dword"):
        pass


if __name__ == "__main__":
    exit(main())
