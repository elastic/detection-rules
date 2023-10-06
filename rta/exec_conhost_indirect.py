# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="32e926c2-2f33-4dd0-ac77-12545331d3e4",
    platforms=["windows"],
    endpoint=[
        {
            'rule_id': '4b61b37d-c569-444a-bafa-e29d221ee55c',
            'rule_name': 'Indirect Command Execution via Console Window Host'
        }
    ],
    siem=[],
    techniques=['T1202'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    conhost = "C:\\Users\\Public\\conhost.exe"
    posh = "C:\\Users\\Public\\posh.exe"
    common.copy_file(EXE_FILE, conhost)
    common.copy_file(EXE_FILE, posh)

    common.execute([conhost, posh], timeout=10, kill=True)
    common.remove_files(conhost, posh)


if __name__ == "__main__":
    exit(main())
