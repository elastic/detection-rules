# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="146cf978-05f2-4492-843c-46626651db89",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': 'b83a7e96-2eb3-4edf-8346-427b6858d3bd',
        'rule_name': 'Creation or Modification of Domain Backup DPAPI private key'
    }],
    techniques=['T1552', 'T1552.004', 'T1555'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    fake_dpapi = "C:\\Users\\Public\\ntds_capi_test.pfx"

    # Execute command
    common.execute([powershell, "/c", f"echo AAAAAAAAAA | Out-File {fake_dpapi}"], timeout=10)
    common.remove_files(fake_dpapi)


if __name__ == "__main__":
    exit(main())
