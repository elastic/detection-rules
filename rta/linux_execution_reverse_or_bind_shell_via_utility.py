# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys
from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="8f5607f7-4c55-4458-b908-b2cb22c54cf4",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Reverse or Bind Shell via Suspicious Utility",
            "rule_id": "bb330560-0042-48a5-8232-7f2012d6e440",
        },
    ],
    techniques=["T1059", "T1071"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    common.log("Creating a fake executable..")
    masquerade = "/tmp/vim"

    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, '-c', "socket"]
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
