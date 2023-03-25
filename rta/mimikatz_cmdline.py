# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="75fdde39-92bb-4a71-a4f1-f70e9c85d6db",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Potential Credential Access via Mimikatz", "rule_id": "86bf5d50-7f5d-44b4-977b-dff222379727"}
    ],
    siem=[],
    techniques=["T1558", "T1003"],
)


@common.requires_os(metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    common.log("Echoing a mimikatz command")
    common.execute([powershell, "echo", "misc::memssp"], timeout=10)


if __name__ == "__main__":
    exit(main())
