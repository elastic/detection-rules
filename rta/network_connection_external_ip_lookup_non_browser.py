# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="07edc3ea-2cf8-4a8b-aa2f-6b10f1c46838",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '1d72d014-e2ab-4707-b056-9b96abe7b511',
        'rule_name': 'External IP Lookup from Non-Browser Process'
    }],
    techniques=['T1016', 'T1016.001', 'T1614'],
)


@common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    common.execute([powershell, "/c", "iwr api.ipify.org -UseBasicParsing"], timeout=10)


if __name__ == "__main__":
    exit(main())
