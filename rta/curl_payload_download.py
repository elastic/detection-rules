# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="bf7645b2-d0cf-428d-a158-b1479160e60c",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Payload Downloaded by Process Running in Suspicious Directory",
            "rule_id": "04d124d4-2be7-405e-b830-9494f927a51e",
        }
    ],
    siem=[],
    techniques=["T1105"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/testfile"
    common.create_macos_masquerade(masquerade)

    # Execute command
    common.log("Launching fake curl commands to download payload")
    common.execute([masquerade, "childprocess", "curl", "portquiz.net"], timeout=5, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
