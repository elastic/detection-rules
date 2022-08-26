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
            "rule_name": "Microsoft Office Process Setting Persistence via Startup",
            "rule_id": "2b8ea430-897d-486c-85a8-add9d7072ff3",
        }
    ],
}
TACTICS = ["TA0003", "TA0001"]
RTA_ID = "ea9a54fe-62ed-4825-b302-0ebbee22233f"
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(PLATFORMS)
def main():
    powershell = "C:\\Users\\Public\\posh.exe"
    temp = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\temp_persist.exe"
    binary = "C:\\Users\\Public\\winword.exe"
    common.copy_file(EXE_FILE, powershell)
    common.copy_file(powershell, binary)

    # Execute command
    common.log("Writing to startup folder using fake winword")
    common.execute([binary, "/c", f"Copy-Item {powershell} '{temp}'"])

    common.remove_files(binary, temp)


if __name__ == "__main__":
    exit(main())
