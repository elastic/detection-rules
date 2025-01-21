# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="a078ecca-e8b8-4ae8-a76c-3238e74ca34d",
    platforms=["linux"],
    endpoint=[
        {"rule_id": "13fd98ce-f1c3-423f-9441-45c50eb462c0", "rule_name": "Attempt to etablish VScode Remote Tunnel"},
    ],
    siem=[],
    techniques=["T1102", "T1059"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    masquerade = "/tmp/code"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    # Execute command
    common.log("Executing Fake commands to test Attempt to etablish VScode Remote Tunnel")
    common.execute([masquerade, "tunnel"], timeout=10, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
