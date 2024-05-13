# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
import os

metadata = RtaMetadata(
    uuid="11b447ca-6ad4-4597-a048-2585b27762ea",
    platforms=["linux"],
    endpoint=[{"rule_name": "Shell Command Execution via kworker", "rule_id": "94943f02-5580-4d1d-a763-09e958bd0f57"}],
    siem=[],
    techniques=["T1036", "T1059"],
)


@common.requires_os(metadata.platforms)
def main():
    masquerade_script = "/tmp/kworker_evasion.sh"
    with open(masquerade_script, "w") as f:
        f.write("#!/bin/bash\n")
        f.write("sh -c 'whoami'\n")

    # Make the script executable
    os.chmod(masquerade_script, 0o755)

    # Execute the script
    common.log("Launching fake command to simulate a kworker execution")
    os.system(masquerade_script)

    # Cleanup
    os.remove(masquerade_script)


if __name__ == "__main__":
    exit(main())
