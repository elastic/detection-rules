# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="4aa10c2d-3839-4ed3-8ca6-a88fdd32bdef",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': 'e94262f2-c1e9-4d3f-a907-aeab16712e1a',
        'rule_name': 'Unusual Executable File Creation by a System Critical Process'
    }],
    techniques=['T1211'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    smss = "C:\\Users\\Public\\smss.exe"
    fake_exe = "C:\\Users\\Public\\a.exe"
    common.copy_file(EXE_FILE, smss)

    # Execute command
    common.execute([smss, "/c", f"echo AAAAAAAAAA | Out-File {fake_exe}"], timeout=10)
    common.remove_files(fake_exe, smss)


if __name__ == "__main__":
    exit(main())
