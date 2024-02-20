# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="7143aab0-c4f3-43da-a11e-aca589887860",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '76fd43b7-3480-4dd9-8ad7-8bd36bfad92f',
        'rule_name': 'Potential Remote Desktop Tunneling Detected'
    }],
    techniques=['T1572'],
)


@common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    common.execute([powershell, "/c", "echo", "127.0.0.1:3389", "-ssh"], timeout=10)


if __name__ == "__main__":
    exit(main())
