# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="6a5977f6-ed19-446e-a441-e325cff7772b",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Potential curl CVE-2023-38545 Exploitation",
            "rule_id": "0c188a15-30f5-445c-8655-95c7f93ace88",
        },
    ],
    siem=[
        {
            "rule_name": "Potential curl CVE-2023-38545 Exploitation",
            "rule_id": "f41296b4-9975-44d6-9486-514c6f635b2d",
        },
    ],
    techniques=["T1203"],
)


@common.requires_os(metadata.platforms)
def main() -> None:
    masquerade = "/tmp/curl"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    payload = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    payload += "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    payload += "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    # Execute command
    common.log("Launching fake command to simulate a buffer overflow")
    common.execute([masquerade, "--proxy", payload], timeout=5, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
