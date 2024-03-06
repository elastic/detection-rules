# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import subprocess

from . import RtaMetadata, common

metadata = RtaMetadata(
    uuid="a5603982-8b43-4ea9-b8de-112d9817e12d",
    platforms=["linux"],
    endpoint=[{"rule_name": "Linux Reverse Shell", "rule_id": "52206861-4570-4b8b-a73e-4ef0ea379a4c"}],
    siem=[],
    techniques=["T1059", "T1071"],
)


@common.requires_os(metadata.platforms)
def main() -> None:
    common.log("Creating the bash command to execute to get the proper parent/child relationship in place...")
    # Bash command that attempts a network connection and then starts a new bash process with the -i flag
    bash_command = 'exec 3<>/dev/tcp/8.8.8.8/53; echo -e "Connection Test" >&3; exec 3<&-; exec 3>&-; exec bash -i'
    common.log("Executing the bash command...")
    # Use subprocess.Popen to execute the bash command
    subprocess.Popen(["bash", "-c", bash_command])  # noqa: S603 S607
    common.log("Simulation successful!")


if __name__ == "__main__":
    main()
