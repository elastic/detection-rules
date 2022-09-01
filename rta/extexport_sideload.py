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
            "rule_name": "Execution via Internet Explorer Exporter",
            "rule_id": "e13a65b7-f46f-4c7f-85cf-7e59170071fa",
        },
        {
            "rule_name": "Execution via Renamed Signed Binary Proxy",
            "rule_id": "b0207677-5041-470b-981d-13ab956cf5b4",
        },
    ],
}
TECHNIQUES = ["T1218"]
RTA_ID = "bbbfc3e3-e1ba-45ad-9d30-cbbe115a0c6c"
RENAMER = common.get_path("bin", "rcedit-x64.exe")
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(PLATFORMS)
def main():
    dll = "C:\\Users\\Public\\sqlite3.dll"
    posh = "C:\\Users\\Public\\posh.exe"
    rcedit = "C:\\Users\\Public\\rcedit.exe"
    common.copy_file(RENAMER, dll)
    common.copy_file(RENAMER, rcedit)
    common.copy_file(EXE_FILE, posh)

    # Execute command
    common.log("Modifying the OriginalFileName attribute")
    common.execute(
        [rcedit, posh, "--set-version-string", "OriginalFilename", "extexport.exe"]
    )

    common.log("Executing modified binary with extexport.exe original file name")
    common.execute([posh], timeout=10, kill=True)

    common.remove_files(dll, posh, rcedit)


if __name__ == "__main__":
    exit(main())
