# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="2bb1f4df-dc38-45a6-a0f4-54660c93a652",
    platforms=["windows"],
    endpoint=[{"rule_name": "NetWire RAT Registry Modification", "rule_id": "102f340f-1839-4bad-8493-824cc02c4e69"}],
    siem=[],
    techniques=["T1112"],
)


@common.requires_os(metadata.platforms)
def main():
    common.log("Temporarily creating a Netwire RAT-like reg key...")

    key = "SOFTWARE\\Netwire"
    value = "HostId"
    data = "Test"

    with common.temporary_reg(common.HKCU, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
