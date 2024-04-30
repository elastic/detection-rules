# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="a330f58c-c808-45d9-b8be-9c2054285c08",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'f2f46686-6f3c-4724-bd7d-24e31c70f98f', 'rule_name': 'LSASS Memory Dump Creation'}],
    techniques=['T1003', 'T1003.001'],
)


@common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    fake_dmp = "C:\\Users\\Public\\lsass_test.dmp"

    # Execute command
    common.execute([powershell, "/c", f"echo AAAAAAAAAA | Out-File {fake_dmp}"], timeout=5)
    common.remove_file(fake_dmp)


if __name__ == "__main__":
    exit(main())
