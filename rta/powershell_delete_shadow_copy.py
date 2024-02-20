# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="463e513d-1b7e-447c-a019-a340445cea3f",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': 'd99a037b-c8e2-47a5-97b9-170d076827c4',
        'rule_name': 'Volume Shadow Copy Deletion via PowerShell'
    }],
    techniques=['T1490'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    common.execute([powershell, "/c", "Get-WmiObject Win32_ShadowCopy | Remove-WmiObject"], timeout=10)


if __name__ == "__main__":
    exit(main())
