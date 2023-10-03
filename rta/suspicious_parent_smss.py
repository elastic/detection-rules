# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="46463426-0a03-448a-afe3-9215841ec86d",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '05b358de-aa6d-4f6c-89e6-78f74018b43b',
        'rule_name': 'Conhost Spawned By Suspicious Parent Process'
    }],
    techniques=['T1059'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    smss = "C:\\Users\\Public\\smss.exe"
    conhost = "C:\\Users\\Public\\conhost.exe"
    common.copy_file(EXE_FILE, smss)
    common.copy_file(EXE_FILE, conhost)

    # Execute command
    common.execute([smss, "/c", conhost], timeout=2, kill=True)
    common.remove_files(smss, conhost)


if __name__ == "__main__":
    exit(main())
