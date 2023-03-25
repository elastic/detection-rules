# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="5a2a5c20-73f6-4a08-a767-95d242b52708",
    platforms=["windows"],
    endpoint=[
        {"rule_name": "Suspicious Windows Script Process Execution", "rule_id": "ffbab5db-73ae-42fd-a33f-36bf649f41cc"},
        {"rule_name": "Execution from Unusual Directory", "rule_id": "16c84e67-e5e7-44ff-aefa-4d771bcafc0c"},
        {"rule_name": "Binary Masquerading via Untrusted Path", "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f"},
    ],
    siem=[],
    techniques=["T1218", "T1036", "T1059"],
)

EXE_FILE = common.get_path("bin", "renamed_posh.exe")
RENAMER = common.get_path("bin", "rcedit-x64.exe")


@common.requires_os(metadata.platforms)
def main():
    cscript = "C:\\Users\\Public\\cscript.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(EXE_FILE, cscript)
    common.copy_file(RENAMER, rcedit)

    # Execute command
    common.log("Modifying the OriginalFileName attribute")
    common.execute([rcedit, cscript, "--set-version-string", "OriginalFilename", "cscript.exe"])

    cmd = "echo {16d51579-a30b-4c8b-a276-0ff4dc41e755}; iwr google.com -UseBasicParsing"
    common.log("Simulating a suspicious command line and making a web request")
    common.execute([cscript, "-c", cmd], timeout=10)

    common.remove_files(cscript, rcedit)


if __name__ == "__main__":
    exit(main())
