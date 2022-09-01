# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common

PLATFORMS = ["windows"]
TRIGGERED_RULES = {
    "SIEM": [],
    "ENDPOINT": [
        {
            "rule_name": "Scriptlet Proxy Execution via PubPrn",
            "rule_id": "0d4454a7-c682-4085-995c-300973c5bdea",
        },
        {
            "rule_name": "Execution from Unusual Directory",
            "rule_id": "16c84e67-e5e7-44ff-aefa-4d771bcafc0c",
        },
        {
            "rule_name": "Binary Masquerading via Untrusted Path",
            "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f",
        },
    ],
}
TECHNIQUES = ["T1216", "T1218", "T1036", "T1059"]
RTA_ID = "8b5119a5-9f78-492a-8448-ff726b0e0b4f"
EXE_FILE = common.get_path("bin", "renamed_posh.exe")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(PLATFORMS)
def main():
    cscript = "C:\\Users\\Public\\cscript.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"

    common.copy_file(RENAMER, rcedit)
    common.copy_file(EXE_FILE, cscript)

    cmd = "127.0.0.1 script:https://domain.com/folder/file.sct"
    # Execute command
    common.log("Modifying the OriginalFileName attribute")
    common.execute(
        [rcedit, cscript, "--set-version-string", "OriginalFileName", "cscript.exe"],
        timeout=10,
    )
    common.execute([cscript, "/c", "echo", cmd], timeout=5, kill=True)

    common.remove_files(cscript, rcedit)


if __name__ == "__main__":
    exit(main())
