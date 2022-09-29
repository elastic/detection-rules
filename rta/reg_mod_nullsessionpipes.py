# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="a6263f00-58b4-4555-b88f-9d66a7395891",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Suspicious NullSessionPipe Registry Modification",
            "rule_id": "11d374d8-2dad-4d9b-83a2-ee908eac8269",
        }
    ],
    siem=[],
    techniques=["T1021", "T1112"],
)


@common.requires_os(metadata.platforms)
def main():
    common.log("Modifying NullSessionPipes reg key...")

    key = "SYSTEM\\CurrentControlSet\\services\\LanmanServer\\Parameters"
    value = "NullSessionPipes"
    data = "RpcServices"

    with common.temporary_reg(common.HKLM, key, value, data):
        pass


if __name__ == "__main__":
    exit(main())
