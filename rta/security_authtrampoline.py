# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="dd39e94e-bfd7-467c-b20d-662d84c0b97e",
    platforms=["macos"],
    endpoint=[],
    siem=[
        {
            "rule_name": "Execution with Explicit Credentials via Scripting",
            "rule_id": "f0eb70e9-71e9-40cd-813f-bf8e8c812cb1",
        }
    ],
    techniques=["T1078", "T1548", "T1059"],
)


@common.requires_os(metadata.platforms)
def main():

    # create masquerades
    masquerade = "/tmp/security_authtrampoline"
    common.create_macos_masquerade(masquerade)

    # Execute commands
    common.log("Launching fake security_authtrampoline process commands to mimic root execution.")
    common.execute([masquerade], timeout=5, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
