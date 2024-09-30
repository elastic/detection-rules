# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="20b06a60-46da-4a27-8e72-df8bf0de37ad",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Base64 or Xxd Decode Argument Evasion",
            "rule_id": "789f8a41-00cb-40cb-b41f-c2e1611b1245",
        },
    ],
    techniques=["T1027", "T1140", "T1059", "T1204"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    common.log("Creating a fake executable..")
    masquerade = "/tmp/xxd"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, "-pevil ", "-revil "]
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
