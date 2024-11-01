# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="b3c8c616-15a5-45fd-970a-c44c18e59578",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "File Downloaded via Curl or Wget to Hidden Directory",
            "rule_id": "dc1cee03-4923-4c6b-b00b-8a5c323bb753",
        },
    ],
    techniques=["T1564"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    common.log("Creating a fake executable..")
    masquerade = "/tmp/curl"

    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, "--output", "/dev/shm/evil"]
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
