# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="c5b8e9c5-59c6-4316-8e73-cd4f5a9a2761",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '84da2554-e12a-11ec-b896-f661ea17fbcd', 'rule_name': 'Enumerating Domain Trusts via NLTEST.EXE'}],
    techniques=['T1482'],
)


@common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    common.execute([powershell, "/c", "nltest.exe /DCLIST:$env:USERDNSDOMAIN"], timeout=10)


if __name__ == "__main__":
    exit(main())
