# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="33f3ebda-7776-4cec-933b-48e85d707d61",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Suspicious Process Spawned from MOTD Detected",
            "rule_id": "b9b3922a-59ee-407c-8773-31b98bf9b18d",
        },
    ],
    siem=[
        {
            "rule_name": "Suspicious Process Spawned from MOTD Detected",
            "rule_id": "4ec47004-b34a-42e6-8003-376a123ea447",
        },
    ],
    techniques=[""],
)


@common.requires_os(metadata.platforms)
def main() -> None:
    common.log("Creating a fake MOTD executable..")
    masquerade = "/etc/update-motd.d/socat"
    dir_path = "/etc/update-motd.d/"
    source = common.get_path("bin", "netcon_exec_chain.elf")
    common.log("Granting directory permissions for copy")
    common.execute(["sudo", "chmod", "777", dir_path])
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, "exec", "-c", "nc -vz localhost 22"]

    common.log("Simulating MOTD netcat activity..")
    common.execute([*commands], timeout=5)
    common.log("MOTD netcat simulation successful!")
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.execute(["sudo", "chmod", "755", dir_path])
    common.log("RTA completed!")


if __name__ == "__main__":
    sys.exit(main())
