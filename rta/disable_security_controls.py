# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="4eceac28-10c3-425f-a007-c03a9b57956f",
    platforms=["linux"],
    endpoint=[
        {
            "rule_id": "b63df89d-ac6f-44d7-80fa-ddf038295e42",
            "rule_name": "Attempt to Disable Linux Security and Logging Controls",
        },
    ],
    siem=[],
    techniques=["T1562", "T1562.001"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    masquerade = "/tmp/systemctl"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    # Execute command
    common.log("Launching fake builtin commands for disabling security controls")
    command = "stop"
    command1 = "apparmor"
    common.execute([masquerade, command, command1], timeout=10, kill=True, shell=True)  # noqa: S604
    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
