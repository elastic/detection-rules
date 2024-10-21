# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys
from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="074901e7-118b-4536-bbed-0e57c319ba2a",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Base64 Shebang Payload Decoded via Built-in Utility",
            "rule_id": "e659b4b9-5bbf-4839-96b9-b489334b4ca1",
        },
    ],
    techniques=["T1027", "T1140", "T1059", "T1204"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    common.log("Creating a fake executable..")
    masquerade = "/tmp/base64"

    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, '-d', 'IyEvdXNyL2Jpbi9weXRob24']
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
