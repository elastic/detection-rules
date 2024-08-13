# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="2b07eb19-c71e-4e79-b0b6-a3850bdbf273",
    platforms=["linux"],
    endpoint=[],
    siem=[],
    techniques=["T1562", "T1562.001"]
)


@common.requires_os(*metadata.platforms)
def main():

    masquerade = "/tmp/ufw"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    # Execute command
    common.log("Launching fake builtin commands for disabling iptables")
    command = "disable"
    common.execute([masquerade, command], timeout=10, kill=True, shell=True)
    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
