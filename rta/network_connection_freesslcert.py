# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="9261a9ca-53ed-483c-967a-3f7a8f93e0ea",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': 'e3cf38fa-d5b8-46cc-87f9-4a7513e4281d',
        'rule_name': 'Connection to Commonly Abused Free SSL Certificate Providers'
    }],
    techniques=['T1573'],
)


@common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    common.execute([powershell, "/c", "Test-NetConnection -ComputerName www.letsencrypt.org -Port 443"], timeout=10)


if __name__ == "__main__":
    exit(main())
