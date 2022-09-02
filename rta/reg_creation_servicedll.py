# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="58b3052d-4242-4b41-9f28-b04ce5962761",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Suspicious Windows Service DLL Creation", "rule_id": "2c624716-75a1-42d9-bcb8-1defcb9bded9"}
    ],
    siem=[],
    techniques=["T1543"],
)


@common.requires_os(metadata.platforms)
def main():
    common.log("Temporarily creating a Service DLL reg key...")

    key = "Software"
    value = "ServiceDLL"
    data = "ServiceDLL"

    with common.temporary_reg(common.HKCU, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
