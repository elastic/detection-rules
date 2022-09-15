# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="92407d57-e5ce-41b1-933a-7cad26158802",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Potential Virtual Machine Fingerprinting via Grep",
            "rule_id": "e5c0963c-0367-4d24-bdf2-5af3a233e57b",
        }
    ],
    siem=[{"rule_name": "Virtual Machine Fingerprinting via Grep", "rule_id": "c85eb82c-d2c8-485c-a36f-534f914b7663"}],
    techniques=["T1082", "T1497"],
)


@common.requires_os(metadata.platforms)
def main():

    common.log("Executing egrep commands to fingerprint virtual machine.")
    common.execute(["egrep", "-i", '"Manufacturer: (parallels|vmware|virtualbox)"'], shell=True)


if __name__ == "__main__":
    exit(main())
