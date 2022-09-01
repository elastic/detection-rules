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
            "rule_name": "Suspicious Execution via Microsoft Office Add-Ins",
            "rule_id": "9efd977a-6d4a-4cc8-8ab3-355587b0ef69",
        }
    ],
}
TECHNIQUES = ["T1137", "T1566"]
RTA_ID = "65c661e6-7a15-45c0-97ad-0635eda560ba"
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(PLATFORMS)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    winword = "C:\\Users\\Public\\winword.exe"
    common.copy_file(EXE_FILE, winword)

    # Execute command
    common.execute(
        [powershell, "/c", winword, "/c", "echo", "doc.wll"], timeout=5, kill=True
    )
    common.remove_file(winword)


if __name__ == "__main__":
    exit(main())
