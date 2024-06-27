# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="9b0bbe6d-2116-4327-930b-51e3e5097487",
    platforms=["linux"],
    endpoint=[{"rule_name": "Potential Linux Hack Tool Launched", "rule_id": "3337a10c-e950-4827-a44e-96a688fba221"}],
    siem=[{"rule_name": "Potential Linux Hack Tool Launched", "rule_id": "1df1152b-610a-4f48-9d7a-504f6ee5d9da"}],
    techniques=[""],
)


@common.requires_os(*metadata.platforms)
def main() -> None:
    masquerade = "/tmp/crackmapexec"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    # Execute command
    common.log("Launching fake command to simulate a CME process")
    common.execute([masquerade], timeout=5, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    sys.exit(main())
