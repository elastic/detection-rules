# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="6e84852e-b8a2-4158-971e-c5148d969d2a",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'eda499b8-a073-4e35-9733-22ec71f57f3a', 'rule_name': 'AdFind Command Activity'}],
    techniques=['T1018', 'T1069', 'T1069.002', 'T1087', 'T1087.002', 'T1482'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    adfind = "C:\\Users\\Public\\adfind.exe"
    common.copy_file(EXE_FILE, adfind)

    # Execute command
    common.execute([adfind, "/c", "echo", "domainlist"], timeout=10)
    common.remove_file(adfind)


if __name__ == "__main__":
    exit(main())
