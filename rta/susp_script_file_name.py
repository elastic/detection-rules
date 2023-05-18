# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="84579cd0-2b30-4846-9b4e-9663ae2c400a",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Suspicious Windows Script File Name", "rule_id": "8c69476a-d8ea-46da-8052-6a4f9254125c"},
        {"rule_name": "Execution from Unusual Directory", "rule_id": "16c84e67-e5e7-44ff-aefa-4d771bcafc0c"},
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
        {
            "rule_name": "Script Execution via Microsoft HTML Application",
            "rule_id": "f0630213-c4c4-4898-9514-746395eb9962",
        },
    ],
    siem=[],
    techniques=["T1036", "T1218", "T1566", "T1059"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(metadata.platforms)
def main():
    mshta = "C:\\Users\\Public\\mshta.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"

    common.copy_file(RENAMER, rcedit)
    common.copy_file(EXE_FILE, mshta)

    cmd = "ls ~\\Downloads\\*.pdf.js"
    # Execute command
    common.log("Modifying the OriginalFileName attribute")
    common.execute(
        [rcedit, mshta, "--set-version-string", "OriginalFileName", "mshta.exe"],
        timeout=10,
    )
    common.execute([mshta, "/c", cmd], timeout=5, kill=True)

    common.remove_files(mshta, rcedit)


if __name__ == "__main__":
    exit(main())
