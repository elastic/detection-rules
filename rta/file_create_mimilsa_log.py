# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="4b23eaa2-aa73-43ee-9c10-47ecf01e00aa",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': 'ebb200e8-adf0-43f8-a0bb-4ee5b5d852c6',
        'rule_name': 'Mimikatz Memssp Log File Detected'
    }],
    techniques=['T1003'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    lsass = "C:\\Users\\Public\\lsass.exe"
    fake_log = "C:\\Users\\Public\\mimilsa.log"
    common.copy_file(EXE_FILE, lsass)

    # Execute command
    common.execute([lsass, "/c", f"echo AAAAAAAAAAAA | Out-File {fake_log}"], timeout=10)
    common.remove_files(fake_log, lsass)


if __name__ == "__main__":
    exit(main())
