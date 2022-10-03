# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="ff60d2ca-f5e0-4270-bc86-ef38bd4f9f48",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '0d8ad79f-9025-45d8-80c1-4f0cd3c5e8e5', 'rule_name': 'Execution of File Written or Modified by Microsoft Office'}],
    techniques=[""],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    winword = "C:\\Users\\Public\\winword.exe"
    arp = "C:\\Users\\Public\\arp.exe"
    temp = "C:\\Users\\Public\\temp.exe"
    common.copy_file(EXE_FILE, winword)
    common.copy_file(EXE_FILE, arp)

    # Execute command
    common.execute([winword, "/c", "Copy-Item", arp, temp], timeout=5)
    common.execute([temp], timeout=5, kill=True)
    common.remove_files(winword, arp, temp)


if __name__ == "__main__":
    exit(main())
