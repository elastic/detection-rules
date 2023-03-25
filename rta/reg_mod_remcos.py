# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="0e5a4099-f76d-43f8-aa91-0ed1ad5fed81",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Remcos RAT Registry or File Modification", "rule_id": "9769d372-4115-4ef8-8d7b-aaad05dad9ae"}
    ],
    siem=[],
    techniques=["T1112"],
)


@common.requires_os(metadata.platforms)
def main():
    common.log("Temporarily creating a Remcos RAT alike reg key...")

    key = "SOFTWARE\\Remcos-rta"
    value = "licence"
    data = "RAT"

    with common.temporary_reg(common.HKCU, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
