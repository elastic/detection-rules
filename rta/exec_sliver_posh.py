# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="99180561-08ad-42e7-bcda-078af280ad9c",
    platforms=["windows"],
    endpoint=[
        {
            'rule_id': '14626cac-eb09-4e52-81f1-f87975e8f5ae',
            'rule_name': 'Potential Execution via Sliver Framework'
        }
    ],
    siem=[],
    techniques=['T1059', 'T1059.001'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():

    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    common.execute([powershell, "-NoExit", "-Command",
                    "[Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8"], timeout=5, kill=True)


if __name__ == "__main__":
    exit(main())
