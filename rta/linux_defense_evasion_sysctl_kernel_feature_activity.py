# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="a33dd7f2-65b0-49f3-b172-8830e70577f5",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Suspicious Kernel Feature Activity",
            "rule_id": "dbbd7fb0-8b29-4c96-901d-166dff728a3b",
        },
    ],
    techniques=["T1562", "T1553", "T1082"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    common.log("Creating a fake executable..")
    masquerade = "/tmp/sysctl"

    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, "--write", "/proc/sys/kernel/yama/ptrace_scope"]
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
