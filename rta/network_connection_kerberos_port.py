# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="b7ed774f-f5e8-49bd-995a-a705c979d88f",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '897dc6b5-b39f-432a-8d75-d3730d50c782', 'rule_name': 'Kerberos Traffic from Unusual Process'}],
    techniques=['T1558'],
)


@common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    common.execute([powershell, "/c", "Test-NetConnection -ComputerName portquiz.net -Port 88"], timeout=5)


if __name__ == "__main__":
    exit(main())
