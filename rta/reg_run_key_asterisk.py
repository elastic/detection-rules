# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="13fbcfdc-ba84-414b-aaa6-49b416806c8e",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Registry Run Key Prefixed with Asterisk", "rule_id": "94d35931-5c48-49ed-8c18-d601c4f8aeaa"}
    ],
    siem=[],
    techniques=["T1547"],
)


@common.requires_os(metadata.platforms)
def main():
    common.log("Writing registry key")

    key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    value = "*test"
    data = "test"

    with common.temporary_reg(common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
