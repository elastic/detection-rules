# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="b6b65c6a-830a-4e1c-ace7-3c98362f998b",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '6aace640-e631-4870-ba8e-5fdda09325db',
        'rule_name': 'Exporting Exchange Mailbox via PowerShell'
    }],
    techniques=['T1005', 'T1114', 'T1114.002'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    common.execute([powershell, "/c", "echo", "New-MailboxExportRequest"], timeout=10)


if __name__ == "__main__":
    exit(main())
