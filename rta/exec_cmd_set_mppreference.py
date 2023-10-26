# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="2730b84c-9e39-4647-ba96-0b438aca9575",
    platforms=["windows"],
    endpoint=[],
    siem=[
        {
            'rule_id': 'c8cccb06-faf2-4cd5-886e-2c9636cfcb87',
            'rule_name': 'Disabling Windows Defender Security Settings via PowerShell'
        },
        {
            'rule_id': '2c17e5d7-08b9-43b2-b58a-0270d65ac85b',
            'rule_name': 'Windows Defender Exclusions Added via PowerShell'
        }
    ],
    techniques=['T1562', 'T1562.001', 'T1562.006', 'T1059', 'T1059.001'],
)


@common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    common.execute([powershell, "/c", "Set-MpPreference", "-ExclusionPath", f"{powershell}"], timeout=10)
    common.execute([powershell, "/c", f"Remove-MpPreference -ExclusionPath {powershell}"], timeout=10)


if __name__ == "__main__":
    exit(main())
