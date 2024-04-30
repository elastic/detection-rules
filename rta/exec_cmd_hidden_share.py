# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="19b6d1cd-6342-42f0-9f1d-20185f5b3d95",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': 'fa01341d-6662-426b-9d0c-6d81e33c8a9d', 'rule_name': 'Remote File Copy to a Hidden Share'}],
    techniques=['T1021', 'T1021.002'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    xcopy = "C:\\Users\\Public\\xcopy.exe"
    common.copy_file(EXE_FILE, xcopy)

    # Execute command
    common.execute([xcopy, "/c", "echo", "mv", "A$"], timeout=10)
    common.remove_file(xcopy)


if __name__ == "__main__":
    exit(main())
