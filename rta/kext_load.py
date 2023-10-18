# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="c4ac8740-3dca-4550-831b-e03d21de581d",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "New System Kext File and Immediate Load via KextLoad",
            "rule_id": "de869aa1-c63a-451e-a953-7069ec39ba60",
        }
    ],
    siem=[],
    techniques=["T1547", "T1547.006", "T1059", "T1059.004"],
)


@common.requires_os(*metadata.platforms)
def main():

    # create masquerades
    masquerade = "/tmp/mv"
    common.create_macos_masquerade(masquerade)

    # Execute command"
    common.log("Launching fake commands load Kext file.")
    common.execute([masquerade, "/System/Library/Extensions/*.kext"], timeout=10, kill=True)
    common.execute(["kextload", "test.kext"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
