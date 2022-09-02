# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
import os


metadata = RtaMetadata(
    uuid="d12e0abb-017f-4321-adf2-20843f62b55d",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Potential Discovery of Windows Credential Manager Store",
            "rule_id": "cc60be0e-2c6c-4dc9-9902-e97103ff8df9",
        }
    ],
    siem=[],
    techniques=["T1555"],
)


@common.requires_os(metadata.platforms)
def main():
    appdata = os.getenv("LOCALAPPDATA")
    credmanfile = f"{appdata}\\Microsoft\\Credentials\\a.txt"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command

    common.execute([powershell, "/c", "echo AAAAAAAAAA >", credmanfile], timeout=10)
    common.log("Cat the contents of a sample file in credman folder")
    common.execute([powershell, "/c", "cat", credmanfile], timeout=10)
    common.remove_file(credmanfile)


if __name__ == "__main__":
    exit(main())
