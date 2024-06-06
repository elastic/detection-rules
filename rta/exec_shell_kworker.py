# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import os
import sys
from pathlib import Path

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="11b447ca-6ad4-4597-a048-2585b27762ea",
    platforms=["linux"],
    endpoint=[{"rule_name": "Shell Command Execution via kworker", "rule_id": "94943f02-5580-4d1d-a763-09e958bd0f57"}],
    siem=[],
    techniques=["T1036", "T1059"],
)


@common.requires_os(metadata.platforms)
def main() -> None:
    masquerade_script = Path("/tmp/kworker_evasion.sh")
    with masquerade_script.open("w") as f:
        f.write("#!/bin/bash\n")
        f.write("sh -c 'whoami'\n")

    # Make the script executable
    masquerade_script.chmod(0o755)

    # Execute the script
    common.log("Launching fake command to simulate a kworker execution")
    os.system(str(masquerade_script))  # noqa: S605

    # Cleanup
    masquerade_script.unlink()


if __name__ == "__main__":
    sys.exit(main())
