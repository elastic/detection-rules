# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="88905741-350f-4a20-a363-22be1e71840c",
    platforms=["windows"],
    endpoint=[
        {
            "rule_name": "Access to Windows Passwords Vault via Powershell",
            "rule_id": "7a4d1be2-db47-4545-a08c-9d4b20bad0d0",
        }
    ],
    siem=[],
    techniques=["T1555", "T1059"],
)


@common.requires_os(metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    cmd = "(new-object 'Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials"
    "ContentType=WindowsRuntime').RetrieveAll()"

    # Execute command
    common.execute([powershell, "/c", cmd], timeout=5, kill=True)


if __name__ == "__main__":
    exit(main())
