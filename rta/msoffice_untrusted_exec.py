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
            "rule_name": "Network Connection via Process with Unusual Arguments",
            "rule_id": "95601d8b-b969-4189-9744-090140ae29e6",
        },
        {
            "rule_name": "Untrusted File Execution via Microsoft Office",
            "rule_id": "bb23a662-2d75-4714-837d-4ec9c2e772a5",
        },
        {
            "rule_name": "RunDLL32/Regsvr32 Loads Dropped Executable",
            "rule_id": "901f0c30-a7c5-40a5-80e3-a50c6744632f",
        },
    ],
}
TACTICS = ["TA0002", "TA0005", "TA0001"]
RTA_ID = "9d5af763-b3f9-4b89-96b6-16e0210f9755"
EXE_FILE = common.get_path("bin", "regsvr32.exe")
EXE_FILE2 = common.get_path("bin", "renamed.exe")


@common.requires_os(PLATFORMS)
def main():
    binary = "winword.exe"
    common.copy_file(EXE_FILE2, binary)

    # Execute command
    fake_regsvr = "C:\\Users\\Public\\regsvr32.exe"
    common.log("Dropping executable using fake winword")
    common.execute([binary, "/c", f"copy {EXE_FILE} {fake_regsvr}"])

    common.log("Executing it to create an untrusted child process")
    common.execute([binary, "/c", fake_regsvr])

    common.remove_files(binary, fake_regsvr)


if __name__ == "__main__":
    exit(main())
