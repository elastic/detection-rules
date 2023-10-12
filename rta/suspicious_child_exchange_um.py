# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="9f58f9e7-a0f5-48e6-a924-d437fd626195",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '483c4daf-b0c6-49e0-adf3-0bfa93231d6b',
        'rule_name': 'Microsoft Exchange Server UM Spawning Suspicious Processes'
    }],
    techniques=['T1190'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    umservice = "C:\\Users\\Public\\umservice.exe"
    common.copy_file(EXE_FILE, umservice)

    common.execute([umservice, "/c", EXE_FILE], timeout=5, kill=True)
    common.remove_files(umservice)


if __name__ == "__main__":
    exit(main())
