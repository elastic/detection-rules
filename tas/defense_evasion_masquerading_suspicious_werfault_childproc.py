# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="6b64bdb3-3e1a-489f-9b9e-8aef02d043e0",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '9d110cb3-5f4b-4c9a-b9f5-53f0a1707ae3', 'rule_name': 'Microsoft Build Engine Started by a System Process'}],
    techniques=[""],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(metadata.platforms)
def main():
    werfault = "C:\\Users\\Public\\werfault.exe"
    common.copy_file(EXE_FILE, werfault)

    # Execute command
    common.execute([werfault, "/c", werfault], timeout=2, kill=True)
    common.remove_files(werfault)


if __name__ == "__main__":
    exit(main())
