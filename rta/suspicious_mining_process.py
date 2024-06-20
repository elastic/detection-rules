# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="425ba45e-10eb-4067-93f4-95701d26da3d",
    platforms=["linux"],
    endpoint=[{"rule_id": "fbf9342e-3d1e-4fba-a828-92fa0fb4d21b", "rule_name": "Suspicious Mining Process Events"}],
    siem=[],
    techniques=["T1059", "T1059.004"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    masquerade = "/tmp/systemctl"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    # Execute command
    common.log("Launching fake builtin commands for disabling common mining services by name")
    command = "start"
    command1 = "apache4.service"
    common.execute([masquerade, command, command1], timeout=10, kill=True, shell=True)  # noqa: S604
    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
