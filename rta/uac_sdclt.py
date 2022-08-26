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
            "rule_name": "Binary Masquerading via Untrusted Path",
            "rule_id": "35dedf0c-8db6-4d70-b2dc-a133b808211f",
        },
        {
            "rule_name": "UAC Bypass via Sdclt",
            "rule_id": "e9095298-65e0-40a2-97c9-055de8685645",
        },
    ],
}
TACTICS = ["TA0005", "TA0004"]
RTA_ID = "7d1ca1a2-be0e-4cd8-944f-2da2fc625468"
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(PLATFORMS)
def main():
    sdclt = "C:\\Users\\Public\\sdclt.exe"
    common.copy_file(EXE_FILE, sdclt)

    common.execute(
        [sdclt, "/c", "echo", "/kickoffelev; powershell"], timeout=2, kill=True
    )
    common.remove_files(sdclt)


if __name__ == "__main__":
    exit(main())
