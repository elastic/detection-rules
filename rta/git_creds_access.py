# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
import os


metadata = RtaMetadata(
    uuid="e15ea2ec-c8a9-4203-8d01-d18d1c27fd58",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Sensitive File Access - Cloud Credentials", "rule_id": "39f60a36-8c5a-4703-8576-ad3e8c800a0f"}
    ],
    siem=[],
    techniques=["T1552"],
)


@common.requires_os(metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    gitpath = "C:\\Users\\Public\\.config\\git"

    try:
        os.makedirs(gitpath)
    except Exception:
        pass
    gitcreds = gitpath + "\\credentials"
    cmd = f"echo 'aaaaaa' > {gitcreds}; cat {gitcreds}"
    # Execute command
    common.execute([powershell, "/c", cmd], timeout=10)
    common.remove_file(gitcreds)


if __name__ == "__main__":
    exit(main())
